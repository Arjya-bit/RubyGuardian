"""
Pydantic response models for the RubyGuardian Classifier API.

These models define the structure and serialization of all API responses,
including classification results, model metadata, and health status.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


class ClassificationResult(BaseModel):
    """Result of classifying a single Ruby file."""

    filename: str = Field(
        ...,
        description="Name of the classified file.",
    )
    sha256: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 hash of the file contents.",
    )
    label: str = Field(
        ...,
        description="Classification label: 'benign' or 'malicious'.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score for the assigned label (0.0 to 1.0).",
    )
    malicious_probability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Raw probability that the file is malicious.",
    )
    model_id: str = Field(
        ...,
        description="Identifier of the model used for classification.",
    )
    features: Optional[dict[str, Any]] = Field(
        default=None,
        description="Extracted feature vector, included if requested.",
    )
    warnings: Optional[list[str]] = Field(
        default=None,
        description="Non-fatal warnings encountered during classification.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "filename": "backdoor.rb",
                    "sha256": "a" * 64,
                    "label": "malicious",
                    "confidence": 0.9731,
                    "malicious_probability": 0.9731,
                    "model_id": "ensemble-v1",
                    "features": None,
                    "warnings": None,
                }
            ]
        }
    }


class BatchResult(BaseModel):
    """Aggregated result from a batch classification request."""

    total: int = Field(..., description="Total number of files submitted.")
    classified: int = Field(..., description="Number of files successfully classified.")
    failed: int = Field(..., description="Number of files that failed classification.")
    results: list[ClassificationResult] = Field(
        default_factory=list,
        description="Individual classification results.",
    )
    errors: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Error details for files that failed classification.",
    )


class ModelInfo(BaseModel):
    """Metadata about a loaded classification model."""

    id: str = Field(..., description="Unique model identifier.")
    name: str = Field(..., description="Human-readable model name.")
    description: str = Field(..., description="Brief description of the model.")
    version: str = Field(..., description="Semantic version of the model.")
    framework: str = Field(..., description="ML framework (e.g. scikit-learn, xgboost).")
    input_features: int = Field(..., ge=1, description="Number of input features expected.")
    trained_at: str = Field(..., description="ISO 8601 timestamp of when the model was trained.")
    metrics: dict[str, float] = Field(
        default_factory=dict,
        description="Evaluation metrics (accuracy, f1_score, auc_roc, etc.).",
    )
    file_path: str = Field(..., description="Path to the serialized model artifact.")
    loaded: bool = Field(..., description="Whether the model is currently loaded in memory.")
    loaded_at: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp of when the model was last loaded.",
    )


class HealthStatus(BaseModel):
    """Comprehensive health status of the classifier API service."""

    status: str = Field(
        ...,
        description="Overall health: 'healthy', 'degraded', or 'unhealthy'.",
    )
    version: str = Field(..., description="Application version.")
    uptime_seconds: float = Field(..., ge=0, description="Seconds since service start.")
    started_at: str = Field(..., description="ISO 8601 timestamp of service start.")
    hostname: str = Field(..., description="Hostname of the running instance.")
    checks: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Individual subsystem check results.",
    )
