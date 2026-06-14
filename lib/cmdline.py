# -*- encoding: utf-8 -*-
"""Command line argument parsing."""

import argparse
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SubDomainsBrute v2.0 - A fast subdomain brute-forcing tool",
        epilog="Example: python subDomainsBrute.py -t 500 --format json target.com",
    )
    parser.add_argument("target", help="Target domain to brute force")
    parser.add_argument(
        "-f", "--file",
        dest="sub_file",
        default="subnames.txt",
        help="Subdomain dictionary file (default: subnames.txt)",
    )
    parser.add_argument(
        "--full",
        dest="full_scan",
        action="store_true",
        default=False,
        help="Use full dictionaries (subnames_full.txt, next_sub_full.txt)",
    )
    parser.add_argument(
        "-i", "--ignore-intranet",
        dest="ignore_intranet",
        action="store_true",
        default=False,
        help="Ignore domains pointing to private IP ranges",
    )
    parser.add_argument(
        "-w", "--wildcard",
        dest="force_wildcard",
        action="store_true",
        default=False,
        help="Force scan even if wildcard test indicates a wildcard domain",
    )
    parser.add_argument(
        "-t", "--threads",
        dest="threads",
        type=int,
        default=500,
        help="Number of concurrent coroutines (default: 500)",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        default=None,
        help="Output file name. Use '-' for stdout (default: stdout)",
    )
    parser.add_argument(
        "--format",
        dest="out_format",
        choices=["txt", "json", "csv"],
        default="txt",
        help="Output format (default: txt)",
    )
    parser.add_argument(
        "--rate-limit",
        dest="rate_limit",
        type=int,
        default=0,
        help="Max DNS queries per second (0 = unlimited, default: 0)",
    )
    parser.add_argument(
        "-s", "--dns-server",
        dest="dns_servers",
        action="append",
        default=None,
        help="Specify DNS resolver IP(s). Can be used multiple times.",
    )
    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Enable verbose output",
    )
    parser.add_argument(
        "-q", "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Suppress non-essential output",
    )

    args = parser.parse_args()

    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    return args
