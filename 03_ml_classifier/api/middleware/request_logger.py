"""
Request/response logging middleware for the RubyGuardian Classifier API.

Logs incoming requests and outgoing responses with timing information,
request metadata, and response status. Supports structured logging fields
for integration with log aggregation systems.
"""

import logging
import time
import uuid
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("rubyguardian.middleware.request_logger")

SENSITIVE_HEADERS = {"authorization", "x-api-key", "cookie", "set-cookie"}
SKIP_PATHS = {"/api/v1/health/live"}


def _sanitize_headers(headers: dict) -> dict:
    """Redact sensitive header values for logging."""
    sanitized = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = value
    return sanitized


def _get_client_ip(request: Request) -> str:
    """Extract client IP address, respecting reverse proxy headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client:
        return request.client.host
    return "unknown"


def _estimate_request_size(request: Request) -> Optional[int]:
    """Estimate request body size from Content-Length header."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            return int(content_length)
        except ValueError:
            return None
    return None


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that logs every HTTP request and response.

    Assigns a unique request ID to each request for tracing across
    distributed systems. Measures and logs request processing duration.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        client_ip = _get_client_ip(request)
        method = request.method
        path = request.url.path
        query = str(request.url.query) if request.url.query else ""
        user_agent = request.headers.get("user-agent", "unknown")
        content_type = request.headers.get("content-type", "")
        request_size = _estimate_request_size(request)

        api_key_name = getattr(request.state, "api_key_name", None)

        logger.info(
            "Request  [%s] %s %s%s client=%s user_agent=%s content_type=%s size=%s key=%s",
            request_id[:8],
            method,
            path,
            f"?{query}" if query else "",
            client_ip,
            user_agent[:80],
            content_type,
            request_size,
            api_key_name or "anonymous",
        )

        start_time = time.monotonic()
        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            logger.error(
                "Response [%s] %s %s - 500 INTERNAL ERROR in %.2fms: %s",
                request_id[:8],
                method,
                path,
                duration_ms,
                str(exc),
            )
            raise

        duration_ms = round((time.monotonic() - start_time) * 1000, 2)
        response_size = response.headers.get("content-length", "unknown")

        log_level = logging.INFO
        if response.status_code >= 500:
            log_level = logging.ERROR
        elif response.status_code >= 400:
            log_level = logging.WARNING

        logger.log(
            log_level,
            "Response [%s] %s %s - %d in %.2fms size=%s",
            request_id[:8],
            method,
            path,
            response.status_code,
            duration_ms,
            response_size,
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(duration_ms)
        return response
