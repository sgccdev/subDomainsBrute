# -*- encoding: utf-8 -*-
"""Asyncio-based subdomain scanner (single-process)."""

from __future__ import annotations

import asyncio
import csv
import json
import logging

import re
import string
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiodns

from .common import is_intranet

logger = logging.getLogger("subDomainsBrute")

# pycares/aiodns error codes
_ARES_ENODATA = 1
_ARES_ENOTFOUND = 4
_ARES_ESERVFAIL = 11
_ARES_ETIMEOUT = 12


class RateLimiter:
    """Simple token-bucket rate limiter for DNS queries."""

    def __init__(self, qps: float) -> None:
        self.qps = qps
        self.tokens = float(qps)
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.qps <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.qps, self.tokens + (now - self.last) * self.qps)
            self.last = now
            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.qps
                await asyncio.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0


class SubNameBrute:
    def __init__(
        self,
        domain: str,
        sub_file: Path,
        dns_servers: List[str],
        next_subs: List[str],
        threads: int = 500,
        ignore_intranet: bool = False,
        force_wildcard: bool = False,
        rate_limit: float = 0.0,
    ) -> None:
        self.domain = domain.rstrip(".").lower()
        self.sub_file = sub_file
        self.dns_servers = dns_servers
        self.dns_count = len(dns_servers)
        self.next_subs = next_subs
        self.threads = threads
        self.ignore_intranet = ignore_intranet
        self.force_wildcard = force_wildcard
        self.rate_limiter = RateLimiter(rate_limit)

        self.queue: asyncio.PriorityQueue[Tuple[int, str]] = asyncio.PriorityQueue()
        self.result_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

        self.scan_count = 0
        self.found_count = 0
        self.scan_lock = asyncio.Lock()

        self.found_subs: Set[str] = set()
        self.ip_dict: Dict[Tuple[str, str], int] = {}
        self.timeout_subs: Dict[str, int] = {}
        self.normal_names_set: Set[str] = set()

        # Use a single shared resolver — aiodns/pycares is designed to handle
        # many concurrent queries on one channel; creating hundreds of channels
        # can exhaust file descriptors and trigger internal asyncio warnings.
        self.resolver = aiodns.DNSResolver(tries=1, timeout=4.0)

    # ------------------------------------------------------------------
    # Dictionary loading
    # ------------------------------------------------------------------

    async def load_sub_names(self) -> None:
        normal_lines: List[str] = []
        wildcard_lines: List[Tuple[int, str]] = []
        wildcard_set: Set[str] = set()
        regex_list: List[str] = []
        seen: Set[str] = set()

        with self.sub_file.open(encoding="utf-8") as f:
            for line in f:
                sub = line.strip()
                if not sub or sub in seen:
                    continue
                seen.add(sub)

                brace_count = sub.count("{")
                if brace_count > 0:
                    wildcard_lines.append((brace_count, sub))
                    pat = (
                        sub.replace("{alphnum}", "[a-z0-9]")
                        .replace("{alpha}", "[a-z]")
                        .replace("{num}", "[0-9]")
                    )
                    if pat not in wildcard_set:
                        wildcard_set.add(pat)
                        regex_list.append("^" + re.escape(pat).replace("\\[a-z0-9\\]", "[a-z0-9]+").replace("\\[a-z\\]", "[a-z]+").replace("\\[0-9\\]", "[0-9]+") + "$")
                else:
                    normal_lines.append(sub)
                    self.normal_names_set.add(sub)

        # Deduplicate: remove normal lines that match wildcard patterns
        if regex_list:
            # Build a single combined pattern for efficiency
            combined = "|".join(f"({r})" for r in regex_list)
            compiled = re.compile(combined)
            normal_lines = [ln for ln in normal_lines if not compiled.search(ln)]

        for sub in normal_lines:
            await self.queue.put((0, sub))
        for item in wildcard_lines:
            await self.queue.put(item)

        logger.info("Loaded %d normal + %d wildcard entries", len(normal_lines), len(wildcard_lines))

    # ------------------------------------------------------------------
    # DNS helpers
    # ------------------------------------------------------------------

    def _set_resolver_nameservers(self) -> None:
        if self.dns_servers:
            self.resolver.nameservers = self.dns_servers[:8]

    async def _query_a(self, resolver: aiodns.DNSResolver, name: str) -> Optional[List[str]]:
        await self.rate_limiter.acquire()
        try:
            answers = await resolver.query_dns(name, "A")
            ips = [rec.data.addr for rec in answers.answer if hasattr(rec.data, 'addr')]
            return ips if ips else None
        except aiodns.error.DNSError as e:
            code = e.args[0]
            if code in (_ARES_ENODATA, _ARES_ENOTFOUND):
                return None
            if code in (_ARES_ESERVFAIL, _ARES_ETIMEOUT):
                raise asyncio.TimeoutError()
            raise

    async def _query_cname(self, resolver: aiodns.DNSResolver, name: str) -> Optional[str]:
        await self.rate_limiter.acquire()
        try:
            answers = await resolver.query_dns(name, "CNAME")
            return answers.answer[0].data.cname
        except aiodns.error.DNSError as e:
            code = e.args[0]
            if code in (_ARES_ENODATA, _ARES_ENOTFOUND):
                return None
            if code in (_ARES_ESERVFAIL, _ARES_ETIMEOUT):
                raise asyncio.TimeoutError()
            raise

    # ------------------------------------------------------------------
    # Core scan worker
    # ------------------------------------------------------------------

    async def scan_worker(self, worker_id: int) -> None:
        resolver = self.resolver

        while True:
            try:
                brace_count, sub = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                # No more items right now; yield and retry briefly
                await asyncio.sleep(0.3)
                # If queue is still empty after sleep, we may be done.
                # But other workers might still be adding items, so we need
                # a termination signal.  We use a sentinel on the queue.
                if self.queue.empty():
                    # Give other workers a moment to enqueue more
                    await asyncio.sleep(0.5)
                    if self.queue.empty():
                        break
                continue

            # Expand wildcard patterns
            if brace_count > 0:
                brace_count -= 1
                if "{next_sub}" in sub:
                    for ns in self.next_subs:
                        await self.queue.put((0, sub.replace("{next_sub}", ns)))
                if "{alphnum}" in sub:
                    for ch in string.ascii_lowercase + string.digits:
                        await self.queue.put((brace_count, sub.replace("{alphnum}", ch, 1)))
                elif "{alpha}" in sub:
                    for ch in string.ascii_lowercase:
                        await self.queue.put((brace_count, sub.replace("{alpha}", ch, 1)))
                elif "{num}" in sub:
                    for ch in string.digits:
                        await self.queue.put((brace_count, sub.replace("{num}", ch, 1)))
                continue

            # Actual DNS scan
            if sub in self.found_subs:
                continue

            cur_domain = sub + "." + self.domain
            try:
                async with self.scan_lock:
                    self.scan_count += 1

                ip_list = await self._query_a(resolver, cur_domain)
                if not ip_list:
                    continue

                ips_str = ", ".join(sorted(ip_list))
                if ips_str in ("1.1.1.1", "127.0.0.1", "0.0.0.0", "0.0.0.1"):
                    continue
                if self.ignore_intranet and is_intranet(ip_list[0]):
                    continue

                self.found_subs.add(sub)

                # CNAME lookup
                cname: Optional[str] = None
                try:
                    cname = await self._query_cname(resolver, cur_domain)
                    if cname and cname.endswith(self.domain) and cname not in self.found_subs:
                        cname_sub = cname[: len(cname) - len(self.domain) - 1]
                        if cname_sub and cname_sub not in self.normal_names_set:
                            self.found_subs.add(cname)
                            await self.queue.put((0, cname_sub))
                except Exception:
                    pass

                # Wildcard / anti-burst filtering (same as v1.4)
                first_level_sub = sub.split(".")[-1]
                max_found = 20
                if self.force_wildcard:
                    first_level_sub = ""
                    max_found = 3

                key = (first_level_sub, ips_str)
                self.ip_dict[key] = self.ip_dict.get(key, 0) + 1
                if self.ip_dict[key] > max_found:
                    continue

                async with self.scan_lock:
                    self.found_count += 1

                await self.result_queue.put({
                    "domain": cur_domain,
                    "ips": ip_list,
                    "cname": cname,
                    "timestamp": time.time(),
                })

                # If this subdomain is not a wildcard itself, queue deeper scans
                try:
                    nonce = uuid.uuid4().hex[:12]
                    test_name = f"{nonce}-test-not-existed.{cur_domain}"
                    await self.rate_limiter.acquire()
                    await resolver.query_dns(test_name, "A")
                except aiodns.error.DNSError as e:
                    if e.args[0] == _ARES_ENOTFOUND:  # NXDOMAIN -> safe to deepen
                        if self.queue.qsize() < 50000:
                            for ns in self.next_subs:
                                await self.queue.put((0, ns + "." + sub))
                        else:
                            await self.queue.put((1, "{next_sub}." + sub))
                except Exception:
                    pass

            except asyncio.TimeoutError:
                self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                if self.timeout_subs[sub] <= 1:
                    await self.queue.put((0, sub))
            except aiodns.error.DNSError as e:
                code = e.args[0]
                if code in (_ARES_ENODATA, _ARES_ENOTFOUND):
                    pass
                elif code in (_ARES_ESERVFAIL, _ARES_ETIMEOUT):
                    self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                    if self.timeout_subs[sub] <= 1:
                        await self.queue.put((0, sub))
                else:
                    logger.debug("DNS error for %s: %s", cur_domain, e)
            except Exception as e:
                logger.debug("Unexpected error scanning %s: %s", cur_domain, e)
                with open("errors.log", "a", encoding="utf-8") as ef:
                    ef.write(f"[{type(e).__name__}] {e}\n")

    # ------------------------------------------------------------------
    # Result consumer
    # ------------------------------------------------------------------

    async def result_consumer(
        self, out_path: Optional[Path], fmt: str
    ) -> None:
        seen: Set[str] = set()
        fh = None
        csv_writer = None

        if out_path is not None:
            fh = out_path.open("w", encoding="utf-8", newline="")
        else:
            fh = sys.stdout

        if fmt == "csv":
            csv_writer = csv.writer(fh)
            csv_writer.writerow(["domain", "ips", "cname", "timestamp"])

        try:
            while True:
                item = await self.result_queue.get()
                if item is None:
                    break

                domain = item["domain"]
                if domain in seen:
                    continue
                seen.add(domain)

                if fmt == "txt":
                    ips = ", ".join(sorted(item["ips"]))
                    line = f"{domain.ljust(30)}\t{ips}\n"
                    fh.write(line)
                elif fmt == "json":
                    fh.write(json.dumps(item, ensure_ascii=False) + "\n")
                elif fmt == "csv":
                    if csv_writer:
                        csv_writer.writerow([
                            domain,
                            ", ".join(item["ips"]),
                            item.get("cname") or "",
                            item.get("timestamp", ""),
                        ])

                if hasattr(fh, "flush"):
                    fh.flush()
        finally:
            if fh is not None and fh is not sys.stdout:
                fh.close()

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    async def run(self, out_path: Optional[Path], fmt: str) -> Tuple[int, int]:
        await self.load_sub_names()
        self._set_resolver_nameservers()

        consumer_task = asyncio.create_task(self.result_consumer(out_path, fmt))
        workers = [
            asyncio.create_task(self.scan_worker(i)) for i in range(self.threads)
        ]

        try:
            results = await asyncio.gather(*workers, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception) and not isinstance(r, asyncio.CancelledError):
                    logger.debug("Worker exception: %s", r)
        except asyncio.CancelledError:
            pass
        finally:
            await self.result_queue.put(None)
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass

        return self.found_count, self.scan_count
