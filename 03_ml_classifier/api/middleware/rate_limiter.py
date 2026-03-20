"""
Token bucket rate limiter middleware for the RubyGuardian Classifier API.

Provides global (per-IP) rate limiting independent of API key limits.
Uses an in-memory token bucket algorithm with automatic cleanup of
stale entries to prevent memory leaks.
"""

import logging
import threading
import time
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("rubyguardian.middleware.rate_limiter")

EXEMPT_PATHS = {"/api/v1/health/live", "/api/v1/health/ready"}
CLEANUP_INTERVAL = 300  # seconds between stale bucket cleanups
BUCKET_EXPIRY = 600  # seconds of inactivity before a bucket is removed


class TokenBucket:
    """A single token bucket for rate limiting one client."""

    __slots__ = ("capacity", "tokens", "refill_rate", "last_refill", "last_access")

    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.monotonic()
        self.last_access = time.monotonic()

    def try_consume(self, count: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        self.last_access = now

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

    @property
    def retry_after(self) -> float:
        if self.tokens >= 1.0:
            return 0.0
        deficit = 1.0 - self.tokens
        return deficit / self.refill_rate


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Global per-IP token bucket rate limiter.

    Each unique client IP gets its own token bucket. Buckets are automatically
    cleaned up after a period of inactivity to prevent unbounded memory growth.
    """

    def __init__(self, app, requests_per_minute: int = 120, burst_size: Optional[int] = None):
        super().__init__(app)
        self._requests_per_minute = requests_per_minute
        self._burst_size = burst_size or requests_per_minute * 2
        self._refill_rate = requests_per_minute / 60.0
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For when behind a proxy."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def _get_bucket(self, client_ip: str) -> TokenBucket:
        with self._lock:
            bucket = self._buckets.get(client_ip)
            if bucket is None:
                bucket = TokenBucket(
                    capacity=float(self._burst_size),
                    refill_rate=self._refill_rate,
                )
                self._buckets[client_ip] = bucket
            return bucket

    def _cleanup_stale_buckets(self) -> None:
        now = time.monotonic()
        if now - self._last_cleanup < CLEANUP_INTERVAL:
            return

        with self._lock:
            stale_keys = [
                ip for ip, bucket in self._buckets.items()
                if now - bucket.last_access > BUCKET_EXPIRY
            ]
            for key in stale_keys:
                del self._buckets[key]
            if stale_keys:
                logger.debug("Cleaned up %d stale rate limit buckets", len(stale_keys))
            self._last_cleanup = now

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        self._cleanup_stale_buckets()

        client_ip = self._get_client_ip(request)
        bucket = self._get_bucket(client_ip)

        if not bucket.try_consume():
            retry_after = round(bucket.retry_after, 1)
            logger.warning("Global rate limit exceeded for IP %s", client_ip)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(int(retry_after + 1))},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Global-Remaining"] = str(int(bucket.tokens))
        response.headers["X-RateLimit-Global-Limit"] = str(self._requests_per_minute)
        return response
