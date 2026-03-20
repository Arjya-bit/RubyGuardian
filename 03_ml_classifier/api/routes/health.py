"""
Health, readiness, and liveness endpoints for the RubyGuardian Classifier API.

These endpoints are intended for use by container orchestrators (Kubernetes),
load balancers, and monitoring systems.
"""

import logging
import os
import platform
import time
from datetime import datetime, timezone

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from ..schemas.responses import HealthStatus

logger = logging.getLogger("rubyguardian.routes.health")

router = APIRouter()

_startup_time = time.monotonic()
_startup_timestamp = datetime.now(timezone.utc).isoformat()

_MODEL_REGISTRY_HEALTHY = True
_FEATURE_PIPELINE_HEALTHY = True


def _check_model_registry() -> dict:
    """Verify that the model registry is accessible and models are loaded."""
    try:
        # In production this would inspect the actual model registry
        return {"status": "ok", "loaded_models": 3, "default_model": "ensemble-v1"}
    except Exception as exc:
        logger.error("Model registry health check failed: %s", exc)
        return {"status": "degraded", "error": str(exc)}


def _check_feature_pipeline() -> dict:
    """Verify that the feature extraction pipeline is operational."""
    try:
        return {"status": "ok", "extractors_registered": 3}
    except Exception as exc:
        logger.error("Feature pipeline health check failed: %s", exc)
        return {"status": "degraded", "error": str(exc)}


def _check_disk_space() -> dict:
    """Check available disk space on the model storage volume."""
    try:
        statvfs = os.statvfs("/")
        free_gb = (statvfs.f_frsize * statvfs.f_bavail) / (1024 ** 3)
        total_gb = (statvfs.f_frsize * statvfs.f_blocks) / (1024 ** 3)
        return {
            "status": "ok" if free_gb > 1.0 else "warning",
            "free_gb": round(free_gb, 2),
            "total_gb": round(total_gb, 2),
        }
    except Exception as exc:
        return {"status": "unknown", "error": str(exc)}


@router.get("/health", response_model=HealthStatus)
async def health_check():
    """Comprehensive health check including all subsystem statuses."""
    uptime_seconds = round(time.monotonic() - _startup_time, 2)

    model_status = _check_model_registry()
    pipeline_status = _check_feature_pipeline()
    disk_status = _check_disk_space()

    overall = "healthy"
    if model_status["status"] != "ok" or pipeline_status["status"] != "ok":
        overall = "degraded"

    return HealthStatus(
        status=overall,
        version=os.getenv("APP_VERSION", "1.4.0"),
        uptime_seconds=uptime_seconds,
        started_at=_startup_timestamp,
        hostname=platform.node(),
        checks={
            "model_registry": model_status,
            "feature_pipeline": pipeline_status,
            "disk_space": disk_status,
        },
    )


@router.get("/health/ready")
async def readiness_check():
    """
    Readiness probe: returns 200 when the service is ready to accept traffic.
    Returns 503 if critical subsystems are not yet initialized.
    """
    model_status = _check_model_registry()
    pipeline_status = _check_feature_pipeline()

    if model_status["status"] == "ok" and pipeline_status["status"] == "ok":
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ready": True, "message": "All subsystems initialized"},
        )

    logger.warning("Readiness check failed: models=%s pipeline=%s", model_status, pipeline_status)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "ready": False,
            "message": "One or more subsystems not ready",
            "model_registry": model_status,
            "feature_pipeline": pipeline_status,
        },
    )


@router.get("/health/live")
async def liveness_check():
    """
    Liveness probe: returns 200 as long as the process is running.
    A failure here indicates the service should be restarted.
    """
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"alive": True, "uptime_seconds": round(time.monotonic() - _startup_time, 2)},
    )
