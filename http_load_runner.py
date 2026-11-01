#!/usr/bin/env python3
"""
HTTP Security & Resilience Load Runner (Host-Executed).
Executes bounded, multi-threaded HTTP requests from the host machine
against a specified target host and port to measure service capacity
and validate Fail2ban threshold mitigations.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

DEFAULT_TIMEOUT_SECONDS = 2
DEFAULT_REPORT_INTERVAL = 2


class TokenBucketRateLimiter:
    """Limits the aggregate request emission rate across all concurrent workers."""

    def __init__(self, requests_per_second: int) -> None:
        self.interval = 1.0 / max(1, requests_per_second)
        self.next_request_at = 0.0
        self.lock = threading.Lock()

    def acquire(self, stop_event: threading.Event) -> bool:
        """Blocks until the next scheduled slot is reached or stop_event is set."""
        with self.lock:
            now = time.monotonic()
            scheduled_at = max(now, self.next_request_at)
            self.next_request_at = scheduled_at + self.interval

        delay = max(0.0, scheduled_at - now)
        return not stop_event.wait(delay)


def execute_request(opener: urllib.request.OpenerDirector, url: str, timeout: int) -> str:
    """Performs a single HTTP GET request and returns the status code or 000 on network failure."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SecurityLab-LoadRunner/1.0"},
        method="GET"
    )
    try:
        with opener.open(req, timeout=timeout) as response:
            return str(response.status)
    except urllib.error.HTTPError as err:
        return str(err.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return "000"


def worker_loop(
    url: str,
    deadline: float,
    stop_event: threading.Event,
    rate_limiter: TokenBucketRateLimiter,
    counts: Counter[str],
    counts_lock: threading.Lock,
    timeout: int,
) -> None:
    """Worker thread sending HTTP requests until the deadline or interrupt event."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while not stop_event.is_set() and time.monotonic() < deadline:
        if not rate_limiter.acquire(stop_event):
            break
        if time.monotonic() >= deadline:
            break

        status = execute_request(opener, url, timeout)
        with counts_lock:
            counts[status] += 1


def format_report(target_url: str, counts: Counter[str], is_final: bool = False) -> None:
    """Displays progress telemetry or final summary statistics."""
    total = sum(counts.values())
    ok_count = counts.get("200", 0)
    failed_count = total - ok_count
    timestamp = datetime.now().strftime("%H:%M:%S")

    prefix = "=== FINAL RESULT ===" if is_final else f"[{timestamp}] Live telemetry"
    print(
        f"  {prefix} for {target_url} -> Total: {total} | 200 OK: {ok_count} | Dropped/Failed/Banned: {failed_count}",
        flush=True,
    )
    if is_final and total > 0:
        fail_percent = (failed_count * 100) // total
        print(f"  -> Mitigation / Failure Rate: {fail_percent}% ({failed_count}/{total} requests)", flush=True)


def run_benchmark(
    host: str,
    port: int,
    path: str,
    concurrency: int,
    duration: int,
    requests_per_second: int,
    timeout: int,
) -> bool:
    """Coordinates worker threads to benchmark target service capacity."""
    target_url = f"http://{host}:{port}{path}"
    print(f"\nTarget Endpoint: {target_url}")
    print(f"Parameters: {concurrency} workers | {requests_per_second} req/s rate limit | {duration}s duration")
    print("-" * 75, flush=True)

    counts: Counter[str] = Counter()
    counts_lock = threading.Lock()
    stop_event = threading.Event()
    rate_limiter = TokenBucketRateLimiter(requests_per_second)
    deadline = time.monotonic() + duration
    interrupted = False

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(
                worker_loop,
                target_url,
                deadline,
                stop_event,
                rate_limiter,
                counts,
                counts_lock,
                timeout,
            )
            for _ in range(concurrency)
        ]

        try:
            while time.monotonic() < deadline:
                time.sleep(min(DEFAULT_REPORT_INTERVAL, max(0.1, deadline - time.monotonic())))
                with counts_lock:
                    snapshot = counts.copy()
                format_report(target_url, snapshot)
        except KeyboardInterrupt:
            interrupted = True
            stop_event.set()
            print("\n[!] Execution interrupted by user. Terminating worker pool...", flush=True)
        finally:
            stop_event.set()

        for future in futures:
            future.result()

    with counts_lock:
        final_counts = counts.copy()
    format_report(target_url, final_counts, is_final=True)
    return not interrupted


def parse_arguments() -> argparse.Namespace:
    """Defines and parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="External HTTP Load & Resilience Benchmark Tool for Security Lab",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--host",
        type=str,
        required=True,
        help="Target IP address or hostname to evaluate",
    )
    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="Target TCP port",
    )
    parser.add_argument(
        "--path",
        type=str,
        default="/",
        help="Target URI path",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=50,
        help="Number of concurrent worker threads",
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=20,
        help="Duration of the load test in seconds",
    )
    parser.add_argument(
        "-r", "--rate",
        type=int,
        default=100,
        help="Aggregate requests-per-second upper bound",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="HTTP connection timeout in seconds",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    if not (1 <= args.port <= 65535):
        sys.exit(f"Error: Port must be between 1 and 65535, received {args.port}")

    print("=" * 75)
    print("  HTTP Security Benchmark & Resilience Runner (Host-Executed)")
    print("=" * 75)

    run_benchmark(
        host=args.host,
        port=args.port,
        path=args.path,
        concurrency=args.concurrency,
        duration=args.duration,
        requests_per_second=args.rate,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
