"""
Pydantic request models for the RubyGuardian Classifier API.

These models handle input validation, coercion, and documentation
for all incoming API requests.
"""

from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class ClassifyRequest(BaseModel):
    """Request body for single-file classification via raw content submission."""

    content: str = Field(
        ...,
        min_length=1,
        max_length=10_485_760,
        description="Raw Ruby source code content to classify.",
    )
    filename: str = Field(
        default="untitled.rb",
        max_length=512,
        description="Original filename for reference and extension validation.",
    )
    model_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Specific model to use. If omitted, the default ensemble is used.",
    )
    include_features: bool = Field(
        default=False,
        description="Whether to include the extracted feature vector in the response.",
    )
    threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Custom decision threshold overriding the model default.",
    )

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        """Ensure filename does not contain path traversal characters."""
        sanitized = value.replace("\\", "/").split("/")[-1]
        if not sanitized:
            return "untitled.rb"
        return sanitized

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "content": "require 'net/http'\nuri = URI('http://example.com')\nNet::HTTP.get(uri)",
                    "filename": "sample.rb",
                    "model_id": None,
                    "include_features": True,
                    "threshold": 0.5,
                }
            ]
        }
    }


class BatchClassifyRequest(BaseModel):
    """Request body for batch classification of multiple Ruby source strings."""

    items: list[ClassifyRequest] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of individual classification requests.",
    )
    model_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Model to use for all items. Individual item model_id takes precedence.",
    )
    fail_fast: bool = Field(
        default=False,
        description="If True, stop processing on first classification error.",
    )

    @field_validator("items")
    @classmethod
    def validate_batch_not_empty(cls, value: list) -> list:
        if not value:
            raise ValueError("Batch must contain at least one item.")
        return value


class URLClassifyRequest(BaseModel):
    """Request body for fetching a Ruby file from a URL and classifying it."""

    url: HttpUrl = Field(
        ...,
        description="URL pointing to a Ruby file to fetch and classify.",
    )
    model_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Specific model to use for classification.",
    )
    include_features: bool = Field(
        default=False,
        description="Whether to include the extracted feature vector in the response.",
    )
    verify_ssl: bool = Field(
        default=True,
        description="Whether to verify the remote server's SSL certificate.",
    )
    timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=120.0,
        description="Timeout in seconds for the HTTP fetch request.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "url": "https://raw.githubusercontent.com/example/repo/main/script.rb",
                    "model_id": None,
                    "include_features": False,
                    "verify_ssl": True,
                    "timeout_seconds": 30.0,
                }
            ]
        }
    }
