"""
RubyGuardian ML Classifier API Package.

Provides a FastAPI-based REST API for classifying Ruby scripts
as benign or malicious using an ensemble of ML models.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

__version__ = "1.4.0"
__author__ = "RubyGuardian Security Research Team"

LOG_LEVEL = os.getenv("RUBYGUARDIAN_LOG_LEVEL", "INFO").upper()
LOG_DIR = Path(os.getenv("RUBYGUARDIAN_LOG_DIR", "/var/log/rubyguardian"))
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d) - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def configure_logging() -> logging.Logger:
    """Configure application-wide logging with rotating file handler and stdout."""
    logger = logging.getLogger("rubyguardian")
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    if logger.handlers:
        return logger

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_DIR / "classifier_api.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=10,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except PermissionError:
        logger.warning("Cannot write to log directory %s; file logging disabled", LOG_DIR)

    return logger


logger = configure_logging()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    from .routes import classify, health, models
    from .middleware.auth import APIKeyAuthMiddleware
    from .middleware.rate_limiter import RateLimiterMiddleware
    from .middleware.request_logger import RequestLoggerMiddleware

    app = FastAPI(
        title="RubyGuardian ML Classifier API",
        description="ML-based classification of Ruby scripts for malware detection.",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(RequestLoggerMiddleware)
    app.add_middleware(RateLimiterMiddleware, requests_per_minute=120)
    app.add_middleware(APIKeyAuthMiddleware)

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(classify.router, prefix="/api/v1", tags=["classify"])
    app.include_router(models.router, prefix="/api/v1", tags=["models"])

    logger.info("RubyGuardian Classifier API v%s initialized", __version__)
    return app


app = create_app()
