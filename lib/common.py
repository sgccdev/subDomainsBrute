# -*- encoding: utf-8 -*-
"""Common utilities for subDomainsBrute v2.0."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import string
import sys
import uuid
from pathlib import Path
from typing import List

import aiodns

logger = logging.getLogger("subDomainsBrute")

_ARES_ENOTFOUND = 4
_ARES_ESERVFAIL = 11

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def is_intranet(ip: str) -> bool:
    """Check if an IP address belongs to a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Console / progress helpers
# ---------------------------------------------------------------------------

def get_terminal_width() -> int:
    """Return terminal width or a sensible default."""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def print_msg(msg: str | None = None, line_feed: bool = False) -> None:
    """Overwrite the current line (CR without LF) for status updates on stderr."""
    if msg is None:
        msg = ""
    width = get_terminal_width()
    padded = msg.ljust(width)
    sys.stderr.write("\r" + padded[:width])
    if line_feed:
        sys.stderr.write("\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Dictionary loading
# ---------------------------------------------------------------------------

def load_next_sub(full_scan: bool = False) -> List[str]:
    """Load the secondary subdomain dictionary."""
    next_subs: List[str] = []
    file_name = "dict/next_sub_full.txt" if full_scan else "dict/next_sub.txt"
    path = Path(file_name)
    if not path.exists():
        logger.warning("Next-sub dictionary not found: %s", path)
        return next_subs

    with path.open(encoding="utf-8") as f:
        for line in f:
            sub = line.strip()
            if not sub or sub in next_subs:
                continue
            tmp_set = {sub}
            while tmp_set:
                item = tmp_set.pop()
                if "{alphnum}" in item:
                    for ch in string.ascii_lowercase + string.digits:
                        tmp_set.add(item.replace("{alphnum}", ch, 1))
                elif "{alpha}" in item:
                    for ch in string.ascii_lowercase:
                        tmp_set.add(item.replace("{alpha}", ch, 1))
                elif "{num}" in item:
                    for ch in string.digits:
                        tmp_set.add(item.replace("{num}", ch, 1))
                elif item not in next_subs:
                    next_subs.append(item)
    return next_subs


def get_sub_file_path(sub_file: str, full_scan: bool) -> Path:
    """Resolve the main subdomain dictionary path."""
    if full_scan and sub_file == "subnames.txt":
        return Path("dict/subnames_full.txt")

    p = Path(sub_file)
    if p.exists():
        return p

    p = Path("dict") / sub_file
    if p.exists():
        return p

    logger.error("Names file not found: %s", sub_file)
    sys.exit(-1)


def get_out_file_name(target: str, output: str | None, out_format: str) -> Path | None:
    """Determine the output file path.  None means stdout."""
    if output == "-":
        return None
    if output:
        return Path(output)
    return None


# ---------------------------------------------------------------------------
# DNS server validation
# ---------------------------------------------------------------------------

_TEST_DOMAINS = [
    ("google.com", "A"),
    ("cloudflare.com", "A"),
    ("baidu.com", "A"),
]


async def _test_dns_server(server: str) -> bool:
    """Validate a DNS resolver.

    A good resolver must be able to resolve real domains.  In transparent-proxy
    environments the NXDOMAIN test may false-positive, so we only hard-fail
    when the resolver cannot answer any real query at all.
    """
    resolver = aiodns.DNSResolver(tries=1, timeout=3.0)
    resolver.nameservers = [server]

    # 1. Can it resolve a real domain?
    resolved_any = False
    for domain, rrtype in _TEST_DOMAINS:
        try:
            answers = await resolver.query_dns(domain, rrtype)
            if answers.answer:
                resolved_any = True
                break
        except Exception:
            continue

    if not resolved_any:
        logger.debug("DNS server %s failed all known-domain tests", server)
        return False

    # 2. Soft-check: does it return NXDOMAIN for a non-existent domain?
    # In many corporate / transparent-proxy networks this will fail, so we
    # only log a warning instead of rejecting the resolver outright.
    nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    test_domain = f"{nonce}-test-subdomainsbrute.example.com"
    try:
        await resolver.query_dns(test_domain, "A")
        logger.warning(
            "DNS server %s returns A records for non-existent domains (possible hijacking). "
            "It will still be used, but results may be less reliable.",
            server,
        )
    except aiodns.error.DNSError as e:
        if e.args[0] != 4:
            logger.debug("DNS server %s NXDOMAIN test error: %s", server, e)
    except Exception as e:
        logger.debug("DNS server %s NXDOMAIN test exception: %s", server, e)

    return True


async def _async_load_dns_servers() -> List[str]:
    dns_servers: List[str] = []
    path = Path("dict/dns_servers.txt")
    if not path.exists():
        logger.error("DNS servers list not found: %s", path)
        sys.exit(-1)

    servers_to_test: List[str] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            server = line.strip()
            if server and not server.startswith("#"):
                servers_to_test.append(server)

    logger.info("Validating %d DNS servers ...", len(servers_to_test))
    results = await asyncio.gather(
        *(_test_dns_server(s) for s in servers_to_test), return_exceptions=True
    )

    bad_servers: List[str] = []
    for server, ok in zip(servers_to_test, results):
        if isinstance(ok, Exception):
            bad_servers.append(server)
            continue
        if ok:
            dns_servers.append(server)
            logger.debug("DNS server OK: %s", server)
        else:
            bad_servers.append(server)
            logger.debug("DNS server BAD: %s", server)

    if bad_servers:
        bad_path = Path("bad_dns_servers.txt")
        with bad_path.open("a", encoding="utf-8") as bf:
            for s in bad_servers:
                bf.write(s + "\n")

    logger.info("%d of %d DNS servers validated OK", len(dns_servers), len(servers_to_test))
    if not dns_servers:
        logger.warning("No DNS servers from file responded. Trying system default resolver ...")
        resolver = aiodns.DNSResolver(tries=1, timeout=3.0)
        try:
            answers = await resolver.query_dns("google.com", "A")
            if answers.answer:
                logger.info("System default resolver is working. Using system DNS.")
                return []
        except Exception:
            pass
        logger.error("No valid DNS server found!")
        sys.exit(-1)
    return dns_servers


async def load_dns_servers(override_servers: Optional[List[str]] = None) -> List[str]:
    """Load and validate DNS servers from the dictionary file or use overrides."""
    if override_servers:
        logger.info("Validating %d user-specified DNS servers ...", len(override_servers))
        results = await asyncio.gather(
            *(_test_dns_server(s) for s in override_servers), return_exceptions=True
        )
        good = [s for s, ok in zip(override_servers, results) if isinstance(ok, bool) and ok]
        if good:
            logger.info(
                "%d of %d user-specified DNS servers validated OK",
                len(good),
                len(override_servers),
            )
            return good
        logger.error("None of the specified DNS servers are reachable!")
        sys.exit(-1)
    return await _async_load_dns_servers()


# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------

async def _wildcard_test(domain: str, dns_servers: List[str]) -> str:
    """Detect wildcard DNS responses using random non-existent subdomains."""
    resolver = aiodns.DNSResolver()
    resolver.nameservers = dns_servers[:8]  # use up to 8 resolvers

    # Level 1: random subdomain against target
    nonce1 = uuid.uuid4().hex[:16]
    test_domain1 = f"{nonce1}-wildcard-test.{domain}"
    try:
        answers = await resolver.query_dns(test_domain1, "A")
        a_records = [rec for rec in answers.answer if hasattr(rec.data, 'addr')]
        if not a_records:
            return domain
        ips = ", ".join(sorted(rec.data.addr for rec in a_records))
        logger.warning("Wildcard detected: any-sub.%s  ->  %s", domain, ips)

        # Level 2: deeper wildcard?
        nonce2 = uuid.uuid4().hex[:16]
        test_domain2 = f"{nonce2}-wildcard-test.any-sub.{domain}"
        try:
            answers2 = await resolver.query_dns(test_domain2, "A")
            a_records2 = [rec for rec in answers2.answer if hasattr(rec.data, 'addr')]
            if not a_records2:
                return domain
            ips2 = ", ".join(sorted(rec.data.addr for rec in a_records2))
            logger.warning("Deep wildcard detected: any-sub.any-sub.%s  ->  %s", domain, ips2)
        except Exception:
            pass

        print_msg(line_feed=True)
        print(f"[!] Wildcard domain detected: {domain} resolves to {ips}")
        print("[!] Use -w to force scan anyway\n")
        sys.exit(0)
    except aiodns.error.DNSError as e:
        if e.args[0] == _ARES_ENOTFOUND:  # NXDOMAIN
            pass  # expected
        elif e.args[0] == _ARES_ESERVFAIL:
            logger.warning("DNS server unreachable during wildcard test, assuming no wildcard")
        else:
            logger.debug("Wildcard test DNS error: %s", e)
    except Exception as e:
        logger.debug("Wildcard test exception: %s", e)

    return domain


async def wildcard_test(domain: str, dns_servers: List[str]) -> str:
    """Asynchronous wildcard detection."""
    return await _wildcard_test(domain, dns_servers)


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def user_abort(sig, frame) -> None:  # noqa: ARG001
    raise KeyboardInterrupt
