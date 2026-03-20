#!/usr/bin/env python3
"""
RubyGuardian - Classification API Load Test

Load tests the malware classification REST API using asyncio and aiohttp.
Measures throughput, latency percentiles, error rates, and concurrent
connection handling under various load profiles.

Usage:
    python load_test_api.py --url http://localhost:8080 --duration 60 --concurrency 50
    python load_test_api.py --url http://localhost:8080 --profile ramp_up
"""

import argparse
import asyncio
import json
import os
import random
import statistics
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional

try:
    import aiohttp
except ImportError:
    print("aiohttp is required: pip install aiohttp")
    sys.exit(1)


@dataclass
class RequestResult:
    """Result of a single API request."""
    status: int
    latency_ms: float
    response_size: int
    error: Optional[str] = None
    endpoint: str = ""
    timestamp: float = 0.0


@dataclass
class LoadTestReport:
    """Aggregated load test results."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    error_rate_pct: float = 0.0
    duration_seconds: float = 0.0
    requests_per_second: float = 0.0
    latency_mean_ms: float = 0.0
    latency_median_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    latency_min_ms: float = 0.0
    latency_max_ms: float = 0.0
    total_bytes_received: int = 0
    status_codes: Dict[int, int] = field(default_factory=dict)
    errors: Dict[str, int] = field(default_factory=dict)
    concurrency: int = 0
    endpoint_stats: Dict[str, Dict] = field(default_factory=dict)


# Load test profiles
PROFILES = {
    "smoke": {"duration": 10, "concurrency": 5, "ramp_up": 0},
    "light": {"duration": 30, "concurrency": 20, "ramp_up": 5},
    "moderate": {"duration": 60, "concurrency": 50, "ramp_up": 10},
    "heavy": {"duration": 120, "concurrency": 100, "ramp_up": 15},
    "stress": {"duration": 180, "concurrency": 200, "ramp_up": 20},
    "ramp_up": {"duration": 120, "concurrency": 100, "ramp_up": 60},
    "spike": {"duration": 60, "concurrency": 300, "ramp_up": 2},
}


def generate_sample_payload(size: str = "small") -> Dict:
    """Generate a realistic classification request payload."""
    sizes = {"small": 256, "medium": 2048, "large": 8192}
    data_size = sizes.get(size, 256)

    return {
        "sample_id": f"loadtest-{random.randint(100000, 999999)}",
        "sample_data": os.urandom(data_size).hex(),
        "metadata": {
            "source": "load_test",
            "filename": f"test_gem_{random.randint(1, 100)}.rb",
            "timestamp": time.time(),
        },
        "options": {
            "deep_analysis": random.choice([True, False]),
            "extract_iocs": True,
            "timeout": 30,
        },
    }


# API endpoints to test
ENDPOINTS = [
    {
        "name": "classify",
        "method": "POST",
        "path": "/api/v1/classify",
        "payload_fn": lambda: generate_sample_payload("small"),
        "weight": 40,
    },
    {
        "name": "classify_batch",
        "method": "POST",
        "path": "/api/v1/classify/batch",
        "payload_fn": lambda: {"samples": [generate_sample_payload("small") for _ in range(5)]},
        "weight": 15,
    },
    {
        "name": "health",
        "method": "GET",
        "path": "/api/v1/health",
        "payload_fn": lambda: None,
        "weight": 10,
    },
    {
        "name": "get_sample",
        "method": "GET",
        "path": f"/api/v1/samples/loadtest-{random.randint(1, 100)}",
        "payload_fn": lambda: None,
        "weight": 15,
    },
    {
        "name": "list_samples",
        "method": "GET",
        "path": "/api/v1/samples?limit=20&status=analyzed",
        "payload_fn": lambda: None,
        "weight": 10,
    },
    {
        "name": "get_stats",
        "method": "GET",
        "path": "/api/v1/stats/daily",
        "payload_fn": lambda: None,
        "weight": 10,
    },
]


def select_endpoint() -> Dict:
    """Select an endpoint based on weighted probability."""
    total = sum(e["weight"] for e in ENDPOINTS)
    r = random.randint(1, total)
    cumulative = 0
    for ep in ENDPOINTS:
        cumulative += ep["weight"]
        if r <= cumulative:
            return ep
    return ENDPOINTS[0]


async def make_request(
    session: aiohttp.ClientSession, base_url: str, endpoint: Dict
) -> RequestResult:
    """Execute a single API request and measure latency."""
    url = f"{base_url}{endpoint['path']}"
    method = endpoint["method"]
    payload = endpoint["payload_fn"]()

    start_time = time.perf_counter()
    timestamp = time.time()

    try:
        kwargs = {"timeout": aiohttp.ClientTimeout(total=30)}
        if payload and method == "POST":
            kwargs["json"] = payload

        async with session.request(method, url, **kwargs) as response:
            body = await response.read()
            latency = (time.perf_counter() - start_time) * 1000

            return RequestResult(
                status=response.status,
                latency_ms=latency,
                response_size=len(body),
                endpoint=endpoint["name"],
                timestamp=timestamp,
            )
    except asyncio.TimeoutError:
        latency = (time.perf_counter() - start_time) * 1000
        return RequestResult(
            status=0, latency_ms=latency, response_size=0,
            error="timeout", endpoint=endpoint["name"], timestamp=timestamp,
        )
    except aiohttp.ClientError as e:
        latency = (time.perf_counter() - start_time) * 1000
        return RequestResult(
            status=0, latency_ms=latency, response_size=0,
            error=str(type(e).__name__), endpoint=endpoint["name"], timestamp=timestamp,
        )
    except Exception as e:
        latency = (time.perf_counter() - start_time) * 1000
        return RequestResult(
            status=0, latency_ms=latency, response_size=0,
            error=str(e)[:100], endpoint=endpoint["name"], timestamp=timestamp,
        )


async def worker(
    session: aiohttp.ClientSession,
    base_url: str,
    results: List[RequestResult],
    stop_event: asyncio.Event,
    results_lock: asyncio.Lock,
):
    """Worker coroutine that sends requests until stop signal."""
    while not stop_event.is_set():
        endpoint = select_endpoint()
        result = await make_request(session, base_url, endpoint)
        async with results_lock:
            results.append(result)
        # Small random delay to avoid thundering herd
        await asyncio.sleep(random.uniform(0.01, 0.05))


async def run_load_test(
    base_url: str,
    duration: int,
    concurrency: int,
    ramp_up: int = 0,
) -> LoadTestReport:
    """Run the load test with specified parameters."""
    print(f"\nStarting load test:")
    print(f"  Target:      {base_url}")
    print(f"  Duration:    {duration}s")
    print(f"  Concurrency: {concurrency}")
    print(f"  Ramp-up:     {ramp_up}s")
    print()

    results: List[RequestResult] = []
    results_lock = asyncio.Lock()
    stop_event = asyncio.Event()

    connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        start_time = time.perf_counter()

        if ramp_up > 0 and concurrency > 1:
            # Gradually add workers during ramp-up period
            workers_per_step = max(1, concurrency // min(ramp_up, concurrency))
            step_delay = ramp_up / (concurrency / workers_per_step)
            active = 0

            while active < concurrency and not stop_event.is_set():
                batch = min(workers_per_step, concurrency - active)
                for _ in range(batch):
                    task = asyncio.create_task(
                        worker(session, base_url, results, stop_event, results_lock)
                    )
                    tasks.append(task)
                    active += 1
                elapsed = time.perf_counter() - start_time
                print(f"\r  Ramp-up: {active}/{concurrency} workers ({elapsed:.1f}s)", end="", flush=True)
                if active < concurrency:
                    await asyncio.sleep(step_delay)
            print()
        else:
            for _ in range(concurrency):
                task = asyncio.create_task(
                    worker(session, base_url, results, stop_event, results_lock)
                )
                tasks.append(task)

        # Progress reporting
        remaining = duration - (time.perf_counter() - start_time)
        while remaining > 0:
            wait_time = min(5, remaining)
            await asyncio.sleep(wait_time)
            elapsed = time.perf_counter() - start_time
            remaining = duration - elapsed
            rps = len(results) / elapsed if elapsed > 0 else 0
            print(f"\r  Progress: {elapsed:.0f}/{duration}s | "
                  f"Requests: {len(results)} | "
                  f"RPS: {rps:.1f} | "
                  f"Errors: {sum(1 for r in results if r.error)}",
                  end="", flush=True)

        stop_event.set()
        print("\n  Stopping workers...")

        # Wait for workers to finish with timeout
        await asyncio.gather(*tasks, return_exceptions=True)

    total_duration = time.perf_counter() - start_time
    return build_report(results, total_duration, concurrency)


def build_report(results: List[RequestResult], duration: float, concurrency: int) -> LoadTestReport:
    """Build an aggregated report from individual request results."""
    report = LoadTestReport()
    report.concurrency = concurrency
    report.duration_seconds = round(duration, 2)
    report.total_requests = len(results)

    if not results:
        return report

    successful = [r for r in results if 200 <= r.status < 400]
    failed = [r for r in results if r.status < 200 or r.status >= 400]

    report.successful_requests = len(successful)
    report.failed_requests = len(failed)
    report.error_rate_pct = round(len(failed) / len(results) * 100, 2) if results else 0
    report.requests_per_second = round(len(results) / duration, 2) if duration > 0 else 0
    report.total_bytes_received = sum(r.response_size for r in results)

    # Latency statistics
    latencies = sorted([r.latency_ms for r in results])
    if latencies:
        report.latency_mean_ms = round(statistics.mean(latencies), 2)
        report.latency_median_ms = round(statistics.median(latencies), 2)
        report.latency_min_ms = round(min(latencies), 2)
        report.latency_max_ms = round(max(latencies), 2)
        report.latency_p95_ms = round(latencies[int(len(latencies) * 0.95)], 2)
        report.latency_p99_ms = round(latencies[int(len(latencies) * 0.99)], 2)

    # Status code distribution
    for r in results:
        report.status_codes[r.status] = report.status_codes.get(r.status, 0) + 1

    # Error distribution
    for r in results:
        if r.error:
            report.errors[r.error] = report.errors.get(r.error, 0) + 1

    # Per-endpoint statistics
    by_endpoint = {}
    for r in results:
        by_endpoint.setdefault(r.endpoint, []).append(r)

    for ep_name, ep_results in by_endpoint.items():
        ep_latencies = sorted([r.latency_ms for r in ep_results])
        ep_errors = sum(1 for r in ep_results if r.error)
        report.endpoint_stats[ep_name] = {
            "count": len(ep_results),
            "errors": ep_errors,
            "latency_mean_ms": round(statistics.mean(ep_latencies), 2),
            "latency_p95_ms": round(ep_latencies[int(len(ep_latencies) * 0.95)], 2) if ep_latencies else 0,
        }

    return report


def print_report(report: LoadTestReport):
    """Print a formatted load test report."""
    print("\n" + "=" * 60)
    print("  RubyGuardian API Load Test Results")
    print("=" * 60)
    print(f"  Duration:       {report.duration_seconds}s")
    print(f"  Concurrency:    {report.concurrency}")
    print(f"  Total Requests: {report.total_requests}")
    print(f"  Successful:     {report.successful_requests}")
    print(f"  Failed:         {report.failed_requests}")
    print(f"  Error Rate:     {report.error_rate_pct}%")
    print(f"  Throughput:     {report.requests_per_second} req/s")
    print(f"  Data Received:  {report.total_bytes_received / 1024:.1f} KB")
    print()
    print("  Latency:")
    print(f"    Mean:   {report.latency_mean_ms} ms")
    print(f"    Median: {report.latency_median_ms} ms")
    print(f"    P95:    {report.latency_p95_ms} ms")
    print(f"    P99:    {report.latency_p99_ms} ms")
    print(f"    Min:    {report.latency_min_ms} ms")
    print(f"    Max:    {report.latency_max_ms} ms")
    print()
    print("  Status Codes:")
    for code, count in sorted(report.status_codes.items()):
        print(f"    {code}: {count}")
    if report.errors:
        print()
        print("  Errors:")
        for error, count in sorted(report.errors.items(), key=lambda x: -x[1]):
            print(f"    {error}: {count}")
    print()
    print("  Endpoint Stats:")
    for ep, stats in sorted(report.endpoint_stats.items()):
        print(f"    {ep}: {stats['count']} requests, "
              f"{stats['latency_mean_ms']}ms avg, "
              f"{stats['latency_p95_ms']}ms p95, "
              f"{stats['errors']} errors")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="RubyGuardian API Load Test")
    parser.add_argument("--url", type=str, default="http://localhost:8080", help="Base URL of the API")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--concurrency", type=int, default=50, help="Number of concurrent connections")
    parser.add_argument("--ramp-up", type=int, default=0, help="Ramp-up time in seconds")
    parser.add_argument("--profile", type=str, choices=list(PROFILES.keys()), help="Named load profile")
    parser.add_argument("--output", type=str, default="load_test_results.json", help="Output JSON file")
    args = parser.parse_args()

    if args.profile:
        profile = PROFILES[args.profile]
        duration = profile["duration"]
        concurrency = profile["concurrency"]
        ramp_up = profile["ramp_up"]
        print(f"Using profile: {args.profile}")
    else:
        duration = args.duration
        concurrency = args.concurrency
        ramp_up = args.ramp_up

    report = asyncio.run(run_load_test(args.url, duration, concurrency, ramp_up))
    print_report(report)

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        json.dump(asdict(report), f, indent=2)
    print(f"\nDetailed results saved to {output_path}")


if __name__ == "__main__":
    main()
