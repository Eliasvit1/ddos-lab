#!/usr/bin/env python3
"""Bounded HTTP load comparison for the isolated Fail2ban lab."""

from __future__ import annotations

import os
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

TARGETS = ("victim-protected", "victim-unprotected")
REQUEST_TIMEOUT_SECONDS = 2
REPORT_INTERVAL_SECONDS = 3
MAX_DURATION_SECONDS = 300
MAX_CONCURRENCY = 500
MAX_REQUESTS_PER_SECOND = 500


def setting(name: str, default: int, maximum: int) -> int:
    """Read and validate a bounded positive integer from the environment."""
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as error:
        raise SystemExit(f"{name} must be an integer; got {raw_value!r}") from error

    if not 1 <= value <= maximum:
        raise SystemExit(f"{name} must be between 1 and {maximum}; got {value}")
    return value


def request_status(opener: urllib.request.OpenerDirector, target: str) -> str:
    """Perform one GET and return its HTTP status, or 000 on network failure."""
    request = urllib.request.Request(f"http://{target}/", method="GET")
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return str(response.status)
    except urllib.error.HTTPError as error:
        return str(error.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return "000"


class RateLimiter:
    """Limit aggregate request starts across all workers for one target."""

    def __init__(self, requests_per_second: int) -> None:
        self.interval = 1 / requests_per_second
        self.next_request_at = 0.0
        self.lock = threading.Lock()

    def wait_for_turn(self, stop_event: threading.Event) -> bool:
        with self.lock:
            now = time.monotonic()
            scheduled_at = max(now, self.next_request_at)
            self.next_request_at = scheduled_at + self.interval
        return not stop_event.wait(max(0.0, scheduled_at - now))


def worker(
    target: str,
    deadline: float,
    stop_event: threading.Event,
    rate_limiter: RateLimiter,
    counts: Counter[str],
    counts_lock: threading.Lock,
) -> None:
    """Send requests until this target's fixed deadline or an interrupt."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while not stop_event.is_set() and time.monotonic() < deadline:
        if not rate_limiter.wait_for_turn(stop_event):
            break
        if time.monotonic() >= deadline:
            break
        code = request_status(opener, target)
        with counts_lock:
            counts[code] += 1


def snapshot(counts: Counter[str], counts_lock: threading.Lock) -> Counter[str]:
    with counts_lock:
        return counts.copy()


def report(target: str, counts: Counter[str], final: bool = False) -> None:
    total = sum(counts.values())
    ok = counts["200"]
    failed = total - ok
    label = "RESULT" if final else f"[{datetime.now():%H:%M:%S}] requests so far"
    print(f"  {label} for {target}: total={total} ok(200)={ok} blocked/failed={failed}", flush=True)
    if final and total:
        print(f"  -> {failed * 100 // total}% of responses were non-200", flush=True)


def run_target(
    target: str, concurrency: int, duration: int, requests_per_second: int
) -> bool:
    """Run one bounded target test; return False if interrupted by Ctrl-C."""
    print(
        f"\n--- Target: {target} ({concurrency} workers, "
        f"{requests_per_second} requests/s max, {duration}s) ---",
        flush=True,
    )
    counts: Counter[str] = Counter()
    counts_lock = threading.Lock()
    stop_event = threading.Event()
    rate_limiter = RateLimiter(requests_per_second)
    deadline = time.monotonic() + duration
    interrupted = False

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(
                worker,
                target,
                deadline,
                stop_event,
                rate_limiter,
                counts,
                counts_lock,
            )
            for _ in range(concurrency)
        ]
        try:
            while time.monotonic() < deadline:
                time.sleep(min(REPORT_INTERVAL_SECONDS, deadline - time.monotonic()))
                report(target, snapshot(counts, counts_lock))
        except KeyboardInterrupt:
            interrupted = True
            stop_event.set()
            print("\nStopping workers after Ctrl-C...", flush=True)
        finally:
            stop_event.set()

        for future in futures:
            future.result()

    report(target, snapshot(counts, counts_lock), final=True)
    return not interrupted


def main() -> None:
    duration = setting("DURATION", default=20, maximum=MAX_DURATION_SECONDS)
    concurrency = setting("CONCURRENCY", default=40, maximum=MAX_CONCURRENCY)
    requests_per_second = setting(
        "REQUESTS_PER_SECOND", default=50, maximum=MAX_REQUESTS_PER_SECOND
    )

    print(
        "=== Bounded HTTP lab test: "
        f"{concurrency} workers, up to {requests_per_second} requests/s, "
        f"{duration}s per target; targets run sequentially ===",
        flush=True,
    )
    for target in TARGETS:
        if not run_target(target, concurrency, duration, requests_per_second):
            break

    print("\n=== Test finished; only the configured lab targets were contacted. ===")
    print("A non-200 result can be a ban, an HTTP error, or a connection timeout.")


if __name__ == "__main__":
    main()
