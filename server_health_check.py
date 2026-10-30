#!/usr/bin/env python3
"""Check basic server health: disk, memory, load, HTTP endpoints and TCP ports.

Standard library only. Exit codes follow the Nagios plugin convention:
0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.

Usage:
    python3 server_health_check.py
    python3 server_health_check.py --disk / --disk /var --http https://example.com/health
    python3 server_health_check.py --tcp localhost:5432 --json
    python3 server_health_check.py --quiet   # silent when OK, handy in cron
"""
import argparse
import json
import os
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request

OK, WARN, CRIT, UNKNOWN = "OK", "WARNING", "CRITICAL", "UNKNOWN"
EXIT_CODES = {OK: 0, WARN: 1, CRIT: 2, UNKNOWN: 3}
# CRITICAL outranks UNKNOWN: a confirmed failure matters more than a check that could not run.
SEVERITY = {OK: 0, WARN: 1, UNKNOWN: 2, CRIT: 3}


def result(check, target, status, detail):
    return {"check": check, "target": target, "status": status, "detail": detail}


def grade(value, warn, crit):
    """Map a measured value to a status; higher is worse."""
    if value >= crit:
        return CRIT
    if value >= warn:
        return WARN
    return OK


def worst(results):
    return max((r["status"] for r in results), key=SEVERITY.get, default=OK)


def check_disk(path, warn, crit):
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return result("disk", path, UNKNOWN, str(exc))
    # Same formula as df: blocks reserved for root count as neither used nor available.
    percent = 100 * usage.used / (usage.used + usage.free)
    return result("disk", path, grade(percent, warn, crit),
                  f"{percent:.1f}% used, {usage.free / 1024**3:.1f} GiB free")


def parse_meminfo(text):
    """Return {field: kB} from the contents of /proc/meminfo."""
    fields = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        if rest.split():
            fields[name] = int(rest.split()[0])
    return fields


def check_memory(warn, crit, meminfo="/proc/meminfo"):
    try:
        with open(meminfo) as f:
            info = parse_meminfo(f.read())
        total, available = info["MemTotal"], info["MemAvailable"]
    except (OSError, KeyError, ValueError) as exc:
        return result("memory", "", UNKNOWN, f"cannot read {meminfo} (Linux only): {exc!r}")
    percent = 100 * (total - available) / total
    return result("memory", "", grade(percent, warn, crit),
                  f"{percent:.1f}% used, {available / 1024**2:.1f} GiB available")


def check_load(warn, crit):
    try:
        load5 = os.getloadavg()[1]
    except (AttributeError, OSError) as exc:  # not available on Windows
        return result("load", "", UNKNOWN, f"load average not available: {exc!r}")
    per_cpu = load5 / (os.cpu_count() or 1)
    return result("load", "", grade(per_cpu, warn, crit),
                  f"{per_cpu:.2f} per CPU (5 min average {load5:.2f})")


def check_http(url, timeout):
    start = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
    except ValueError as exc:
        return result("http", url, UNKNOWN, f"invalid URL: {exc}")
    except OSError as exc:  # URLError, timeouts, refused connections
        return result("http", url, CRIT, f"unreachable: {getattr(exc, 'reason', exc)}")
    ms = (time.monotonic() - start) * 1000
    return result("http", url, OK if code < 400 else CRIT, f"HTTP {code} in {ms:.0f} ms")


def parse_hostport(spec):
    host, sep, port = spec.rpartition(":")
    host = host.strip("[]")
    if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {spec!r}")
    return host, int(port)


def check_tcp(host, port, timeout):
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as exc:
        return result("tcp", target, CRIT, f"connect failed: {exc}")
    ms = (time.monotonic() - start) * 1000
    return result("tcp", target, OK, f"open in {ms:.0f} ms")


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--disk", action="append", metavar="PATH",
                   help="filesystem to check, repeatable (default: /)")
    p.add_argument("--http", action="append", default=[], metavar="URL",
                   help="URL that must answer with a status below 400, repeatable")
    p.add_argument("--tcp", action="append", default=[], type=parse_hostport,
                   metavar="HOST:PORT", help="port that must accept connections, repeatable")
    p.add_argument("--disk-warn", type=float, default=80, help="percent used (default: 80)")
    p.add_argument("--disk-crit", type=float, default=90, help="percent used (default: 90)")
    p.add_argument("--mem-warn", type=float, default=85, help="percent used (default: 85)")
    p.add_argument("--mem-crit", type=float, default=95, help="percent used (default: 95)")
    p.add_argument("--load-warn", type=float, default=1.0, help="load per CPU (default: 1.0)")
    p.add_argument("--load-crit", type=float, default=2.0, help="load per CPU (default: 2.0)")
    p.add_argument("--timeout", type=float, default=5, help="network timeout in seconds (default: 5)")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument("--quiet", action="store_true", help="print nothing when everything is OK")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    for name in ("disk", "mem", "load"):
        if getattr(args, f"{name}_warn") > getattr(args, f"{name}_crit"):
            parser.error(f"--{name}-warn must not exceed --{name}-crit")

    results = [check_disk(path, args.disk_warn, args.disk_crit) for path in args.disk or ["/"]]
    results.append(check_memory(args.mem_warn, args.mem_crit))
    results.append(check_load(args.load_warn, args.load_crit))
    results += [check_http(url, args.timeout) for url in args.http]
    results += [check_tcp(host, port, args.timeout) for host, port in args.tcp]
    status = worst(results)

    if args.quiet and status == OK:
        pass
    elif args.json:
        print(json.dumps({"status": status, "checks": results}, indent=2))
    else:
        bad = sum(r["status"] != OK for r in results)
        print(f"{status}: {bad} of {len(results)} checks not OK")
        for r in results:
            print(f"  {r['status']:<8}  {r['check']:<6}  {r['target']:<24}  {r['detail']}")
    return EXIT_CODES[status]


if __name__ == "__main__":
    sys.exit(main())
