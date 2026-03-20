"""
Model management endpoints for the RubyGuardian Classifier API.

Provides routes for listing available models, inspecting model metadata,
and triggering hot-reload of updated model artifacts.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Path, Query, status

from ..schemas.responses import ModelInfo

logger = logging.getLogger("rubyguardian.routes.models")

router = APIRouter()

# In-memory model registry (production would use a persistent store)
_MODEL_REGISTRY: dict[str, dict] = {
    "ensemble-v1": {
        "id": "ensemble-v1",
        "name": "Ensemble Classifier v1",
        "description": "Weighted ensemble of Random Forest, XGBoost, and neural network classifiers.",
        "version": "1.0.3",
        "framework": "scikit-learn + xgboost",
        "input_features": 128,
        "trained_at": "2025-11-20T14:30:00Z",
        "metrics": {"accuracy": 0.967, "f1_score": 0.954, "auc_roc": 0.989},
        "file_path": "/models/ensemble_v1.joblib",
        "loaded": True,
        "loaded_at": datetime.now(timezone.utc).isoformat(),
    },
    "rf-baseline": {
        "id": "rf-baseline",
        "name": "Random Forest Baseline",
        "description": "Standalone Random Forest classifier used as a baseline model.",
        "version": "2.1.0",
        "framework": "scikit-learn",
        "input_features": 128,
        "trained_at": "2025-10-15T09:00:00Z",
        "metrics": {"accuracy": 0.941, "f1_score": 0.928, "auc_roc": 0.972},
        "file_path": "/models/rf_baseline.joblib",
        "loaded": True,
        "loaded_at": datetime.now(timezone.utc).isoformat(),
    },
    "xgb-deep": {
        "id": "xgb-deep",
        "name": "XGBoost Deep Features",
        "description": "XGBoost classifier trained on deep AST and behavioral features.",
        "version": "1.2.1",
        "framework": "xgboost",
        "input_features": 256,
        "trained_at": "2025-12-01T18:45:00Z",
        "metrics": {"accuracy": 0.958, "f1_score": 0.943, "auc_roc": 0.985},
        "file_path": "/models/xgb_deep.json",
        "loaded": True,
        "loaded_at": datetime.now(timezone.utc).isoformat(),
    },
}


@router.get("/models", response_model=list[ModelInfo])
async def list_models(
    loaded_only: bool = Query(False, description="Only return currently loaded models"),
):
    """List all available classification models."""
    models = []
    for model_id, meta in _MODEL_REGISTRY.items():
        if loaded_only and not meta.get("loaded", False):
            continue
        models.append(ModelInfo(**meta))

    logger.info("Listed %d models (loaded_only=%s)", len(models), loaded_only)
    return models


@router.get("/models/{model_id}/info", response_model=ModelInfo)
async def get_model_info(
    model_id: str = Path(..., description="Unique identifier of the model"),
):
    """Retrieve detailed metadata for a specific model."""
    meta = _MODEL_REGISTRY.get(model_id)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model '{model_id}' not found in registry",
        )

    logger.info("Returning info for model %s", model_id)
    return ModelInfo(**meta)


@router.post("/models/{model_id}/reload", response_model=ModelInfo)
async def reload_model(
    model_id: str = Path(..., description="Unique identifier of the model to reload"),
):
    """
    Hot-reload a model from disk.

    This triggers deserialization of the model artifact at its configured
    file path and replaces the in-memory model instance. Useful after
    deploying updated model weights without restarting the service.
    """
    meta = _MODEL_REGISTRY.get(model_id)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model '{model_id}' not found in registry",
        )

    logger.info("Reloading model %s from %s", model_id, meta["file_path"])

    reload_start = time.monotonic()
    try:
        # In production, this would deserialize the model from disk:
        #   model = joblib.load(meta["file_path"])
        #   _loaded_models[model_id] = model
        pass
    except Exception as exc:
        logger.error("Failed to reload model %s: %s", model_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reload model: {exc}",
        )

    reload_duration = round(time.monotonic() - reload_start, 4)
    meta["loaded"] = True
    meta["loaded_at"] = datetime.now(timezone.utc).isoformat()

    logger.info("Model %s reloaded successfully in %.4fs", model_id, reload_duration)
    return ModelInfo(**meta)
