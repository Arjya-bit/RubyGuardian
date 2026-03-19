"""
RubyGuardian ML Classifier -- REST API Application

FastAPI-based REST API for the malware classification service.
Provides endpoints for classifying Ruby scripts, batch classification,
model information, and health checks.
"""

import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import numpy as np
import yaml
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from pydantic import BaseModel, Field

from models.ensemble_classifier import EnsembleMalwareClassifier
from models.training.train_pipeline import TrainPipeline
from feature_extraction import (
    ASTFeatureExtractor,
    StaticAnalyzer,
    StringPatternExtractor,
    APICallExtractor,
    ImportAnalyzer,
    ObfuscationScorer,
)


class ClassificationRequest(BaseModel):
    """Request body for single script classification."""
    source_code: str = Field(..., description="Ruby source code to classify")
    include_features: bool = Field(False, description="Include extracted features in response")


class ClassificationResponse(BaseModel):
    """Response body for classification results."""
    prediction: str
    confidence: float
    probabilities: dict[str, float]
    risk_level: str
    processing_time_ms: float
    features: Optional[dict[str, Any]] = None


class BatchRequest(BaseModel):
    """Request body for batch classification."""
    scripts: list[str] = Field(..., description="List of Ruby source code strings")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    model_loaded: bool
    model_version: Optional[str]
    uptime_seconds: float


# Global state
_state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: load model on startup, cleanup on shutdown."""
    logger.info("Starting RubyGuardian ML Classifier API")
    _state["start_time"] = time.time()

    # Load model
    model_path = Path("models/saved_models/ensemble_latest.pkl")
    if model_path.exists():
        try:
            _state["model"] = EnsembleMalwareClassifier.load(model_path)
            _state["model_loaded"] = True
            logger.info("Ensemble model loaded from {}", model_path)
        except Exception as e:
            logger.warning("Could not load model: {}", e)
            _state["model_loaded"] = False
            _state["model"] = None
    else:
        logger.warning("No saved model found at {}", model_path)
        _state["model_loaded"] = False
        _state["model"] = None

    # Initialize feature extractors
    _state["extractors"] = {
        "ast": ASTFeatureExtractor(),
        "static": StaticAnalyzer(),
        "strings": StringPatternExtractor(),
        "api_calls": APICallExtractor(),
        "imports": ImportAnalyzer(),
        "obfuscation": ObfuscationScorer(),
    }

    yield

    logger.info("Shutting down ML Classifier API")
    _state.clear()


app = FastAPI(
    title="RubyGuardian ML Classifier",
    description="REST API for Ruby malware classification using ML ensemble models",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def extract_features(source_code: str) -> dict[str, Any]:
    """Extract features from Ruby source code using all extractors."""
    features = {}
    for name, extractor in _state["extractors"].items():
        try:
            result = extractor.extract(source_code)
            if isinstance(result, dict):
                features.update(result)
            elif isinstance(result, (list, np.ndarray)):
                features[name] = result
        except Exception as e:
            logger.warning("Extractor {} failed: {}", name, e)
    return features


def features_to_vector(features: dict) -> np.ndarray:
    """Convert feature dictionary to numpy vector for model input."""
    # Flatten nested features into a consistent vector
    values = []
    for key in sorted(features.keys()):
        val = features[key]
        if isinstance(val, (int, float)):
            values.append(float(val))
        elif isinstance(val, bool):
            values.append(1.0 if val else 0.0)
        elif isinstance(val, (list, np.ndarray)):
            values.extend([float(v) for v in val])
    return np.array(values).reshape(1, -1)


def risk_level_from_confidence(prediction: str, confidence: float) -> str:
    """Determine risk level from prediction and confidence."""
    if prediction == "benign":
        return "low" if confidence > 0.8 else "medium"
    if confidence > 0.9:
        return "critical"
    if confidence > 0.7:
        return "high"
    return "medium"


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        model_loaded=_state.get("model_loaded", False),
        model_version="1.0.0" if _state.get("model_loaded") else None,
        uptime_seconds=time.time() - _state.get("start_time", time.time()),
    )


@app.post("/classify", response_model=ClassificationResponse)
async def classify_script(request: ClassificationRequest):
    """Classify a single Ruby script as benign or malicious."""
    if not _state.get("model_loaded"):
        raise HTTPException(503, "Model not loaded. Train a model first.")

    start = time.time()

    features = extract_features(request.source_code)
    feature_vector = features_to_vector(features)

    model = _state["model"]
    prediction = model.predict(feature_vector)[0]
    probabilities = model.predict_proba(feature_vector)[0]

    prob_dict = {
        label: float(prob)
        for label, prob in zip(model.classes_, probabilities)
    }
    confidence = float(max(probabilities))

    elapsed_ms = (time.time() - start) * 1000

    return ClassificationResponse(
        prediction=str(prediction),
        confidence=confidence,
        probabilities=prob_dict,
        risk_level=risk_level_from_confidence(str(prediction), confidence),
        processing_time_ms=round(elapsed_ms, 2),
        features=features if request.include_features else None,
    )


@app.post("/classify/batch")
async def classify_batch(request: BatchRequest):
    """Classify multiple Ruby scripts in batch."""
    if not _state.get("model_loaded"):
        raise HTTPException(503, "Model not loaded.")

    results = []
    for script in request.scripts:
        features = extract_features(script)
        feature_vector = features_to_vector(features)
        model = _state["model"]
        prediction = model.predict(feature_vector)[0]
        probabilities = model.predict_proba(feature_vector)[0]
        confidence = float(max(probabilities))

        results.append({
            "prediction": str(prediction),
            "confidence": confidence,
            "risk_level": risk_level_from_confidence(str(prediction), confidence),
        })

    return {"results": results, "count": len(results)}


@app.post("/classify/file")
async def classify_file(file: UploadFile = File(...)):
    """Classify an uploaded Ruby file."""
    if not _state.get("model_loaded"):
        raise HTTPException(503, "Model not loaded.")

    content = await file.read()
    source_code = content.decode("utf-8", errors="replace")

    features = extract_features(source_code)
    feature_vector = features_to_vector(features)
    model = _state["model"]
    prediction = model.predict(feature_vector)[0]
    probabilities = model.predict_proba(feature_vector)[0]
    confidence = float(max(probabilities))

    return {
        "filename": file.filename,
        "prediction": str(prediction),
        "confidence": confidence,
        "risk_level": risk_level_from_confidence(str(prediction), confidence),
    }


@app.get("/model/info")
async def model_info():
    """Get information about the loaded model."""
    if not _state.get("model_loaded"):
        return {"model_loaded": False}

    model = _state["model"]
    return {
        "model_loaded": True,
        "model_type": type(model).__name__,
        "classes": list(model.classes_) if hasattr(model, "classes_") else [],
        "sub_models": list(model.models.keys()) if hasattr(model, "models") else [],
    }
