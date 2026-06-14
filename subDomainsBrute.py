#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
subDomainsBrute 2.0
A fast subdomain brute-forcing tool for penetration testers.
https://github.com/lijiejie/subDomainsBrute
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from pathlib import Path

import aiodns

from lib.cmdline import parse_args
from lib.common import (
    get_out_file_name,
    get_sub_file_path,
    load_dns_servers,
    load_next_sub,
    print_msg,
    user_abort,
    wildcard_test,
)
from lib.scanner import SubNameBrute


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.INFO
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")

    # Also log errors to file
    fh = logging.FileHandler("errors.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.ERROR)
    fh.setFormatter(logging.Formatter(fmt))
    logging.getLogger().addHandler(fh)


async def progress_reporter(
    scanner: SubNameBrute, interval: float = 0.5
) -> None:
    """Periodically print scan progress."""
    spinner = ["\\", "|", "/", "-"]
    idx = 0
    start = time.time()
    while True:
        await asyncio.sleep(interval)
        elapsed = time.time() - start
        queue_left = scanner.queue.qsize()
        msg = (
            f"[{spinner[idx % 4]}] {scanner.found_count} found, "
            f"{scanner.scan_count} scanned in {elapsed:.1f}s, "
            f"{queue_left} queued"
        )
        print_msg(msg)
        idx += 1
        # Stop when queue is empty and all workers are likely done
        if queue_left == 0:
            await asyncio.sleep(0.5)
            if scanner.queue.qsize() == 0:
                break


def _info(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg)


def _suppress_noisy_dns_warnings(loop, context):
    """Ignore unretrieved-future warnings caused by aiodns/pycares internals."""
    exc = context.get("exception")
    if isinstance(exc, aiodns.error.DNSError) and exc.args[0] == 11:
        return
    loop.default_exception_handler(context)


async def main_async() -> int:
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_suppress_noisy_dns_warnings)

    args = parse_args()
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    target = args.target.lower().strip()
    _info("SubDomainsBrute v2.0  https://github.com/lijiejie/subDomainsBrute", args.quiet)
    _info(f"[+] Target: {target}", args.quiet)

    # Validate & load DNS servers
    dns_servers = await load_dns_servers(args.dns_servers)

    # Load next-level dictionary
    next_subs = load_next_sub(full_scan=args.full_scan)

    # Wildcard test
    if not args.force_wildcard:
        _info("[+] Running wildcard test ...", args.quiet)
        domain = await wildcard_test(target, dns_servers)
    else:
        domain = target

    sub_file = get_sub_file_path(args.sub_file, args.full_scan)
    out_path = get_out_file_name(domain, args.output, args.out_format)

    if out_path is None:
        _info("[+] Output: stdout", args.quiet)
    else:
        _info(f"[+] Output file: {out_path}", args.quiet)

    _info(f"[+] Threads (coroutines): {args.threads}", args.quiet)
    if args.rate_limit > 0:
        _info(f"[+] Rate limit: {args.rate_limit} qps", args.quiet)
    _info("[+] Starting scan ...\n", args.quiet)

    scanner = SubNameBrute(
        domain=domain,
        sub_file=sub_file,
        dns_servers=dns_servers,
        next_subs=next_subs,
        threads=args.threads,
        ignore_intranet=args.ignore_intranet,
        force_wildcard=args.force_wildcard,
        rate_limit=float(args.rate_limit),
    )

    start_time = time.time()
    progress_task = asyncio.create_task(progress_reporter(scanner))
    if args.quiet:
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

    try:
        found, scanned = await scanner.run(out_path, args.out_format)
    except KeyboardInterrupt:
        print_msg(line_feed=True)
        _info("[ERROR] User aborted the scan!", args.quiet)
        if not progress_task.done():
            progress_task.cancel()
        return 130
    finally:
        if not progress_task.done():
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

    elapsed = time.time() - start_time
    print_msg(line_feed=True)
    _info(f"All Done. {found} found, {scanned} scanned in {elapsed:.1f} seconds.", args.quiet)
    if out_path is not None:
        _info(f"Output file is {out_path}", args.quiet)
    return 0


def main() -> int:
    signal.signal(signal.SIGINT, user_abort)
    # pycares on Windows: SelectorEventLoop was required before Python 3.12.
    # In 3.12+ ProactorEventLoop works fine and the old policy API is deprecated.
    if sys.platform == "win32" and sys.version_info < (3, 12):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except AttributeError:
            pass
    try:
        return asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[ERROR] User aborted the scan!")
        return 130


if __name__ == "__main__":
    sys.exit(main())
