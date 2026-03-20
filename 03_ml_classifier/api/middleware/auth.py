"""
API key authentication middleware for the RubyGuardian Classifier API.

Validates requests against a set of configured API keys and enforces
per-key rate limits. Keys are loaded from environment variables or
a configuration file.
"""

import hashlib
import logging
import os
import time
from collections import defaultdict
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("rubyguardian.middleware.auth")

EXEMPT_PATHS = {"/docs", "/redoc", "/openapi.json", "/api/v1/health/live", "/api/v1/health/ready"}
API_KEY_HEADER = "X-API-Key"
AUTH_ENABLED = os.getenv("RUBYGUARDIAN_AUTH_ENABLED", "true").lower() == "true"


class APIKeyRecord:
    """Tracks metadata and per-key rate limiting state."""

    def __init__(self, key_hash: str, name: str, requests_per_minute: int = 60):
        self.key_hash = key_hash
        self.name = name
        self.requests_per_minute = requests_per_minute
        self.tokens = float(requests_per_minute)
        self.max_tokens = float(requests_per_minute)
        self.last_refill = time.monotonic()
        self.total_requests = 0
        self.last_request_at: Optional[float] = None

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        refill_amount = elapsed * (self.requests_per_minute / 60.0)
        self.tokens = min(self.max_tokens, self.tokens + refill_amount)
        self.last_refill = now

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed, False if rate limited."""
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            self.total_requests += 1
            self.last_request_at = time.monotonic()
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until the next token becomes available."""
        if self.tokens >= 1.0:
            return 0.0
        deficit = 1.0 - self.tokens
        return deficit / (self.requests_per_minute / 60.0)


def _load_api_keys() -> dict[str, APIKeyRecord]:
    """Load API keys from environment. Format: RUBYGUARDIAN_API_KEY_<name>=<key>."""
    keys: dict[str, APIKeyRecord] = {}
    for env_key, env_value in os.environ.items():
        if env_key.startswith("RUBYGUARDIAN_API_KEY_"):
            name = env_key[len("RUBYGUARDIAN_API_KEY_"):].lower()
            key_hash = hashlib.sha256(env_value.encode()).hexdigest()
            rate_limit = int(os.getenv(f"RUBYGUARDIAN_RATE_LIMIT_{name.upper()}", "60"))
            keys[key_hash] = APIKeyRecord(key_hash=key_hash, name=name, requests_per_minute=rate_limit)
            logger.info("Loaded API key '%s' (rate limit: %d req/min)", name, rate_limit)

    if not keys:
        # Provide a default development key when none are configured
        dev_key = os.getenv("RUBYGUARDIAN_DEV_KEY", "dev-key-changeme")
        dev_hash = hashlib.sha256(dev_key.encode()).hexdigest()
        keys[dev_hash] = APIKeyRecord(key_hash=dev_hash, name="development", requests_per_minute=120)
        logger.warning("No API keys configured; using default development key")

    return keys


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that validates API key authentication on each request."""

    def __init__(self, app, **kwargs):
        super().__init__(app)
        self._api_keys = _load_api_keys()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not AUTH_ENABLED:
            return await call_next(request)

        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        api_key = request.headers.get(API_KEY_HEADER)
        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key. Provide it via the X-API-Key header."},
            )

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        record = self._api_keys.get(key_hash)
        if record is None:
            logger.warning("Invalid API key attempt from %s", request.client.host if request.client else "unknown")
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid API key."},
            )

        if not record.consume():
            retry_after = round(record.retry_after, 1)
            logger.warning("Rate limit exceeded for key '%s'", record.name)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded.", "retry_after_seconds": retry_after},
                headers={"Retry-After": str(int(retry_after + 1))},
            )

        request.state.api_key_name = record.name
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(int(record.tokens))
        response.headers["X-RateLimit-Limit"] = str(record.requests_per_minute)
        return response
