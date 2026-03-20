"""
Classification endpoints for the RubyGuardian ML Classifier API.

Provides routes for classifying individual Ruby files, batches of files,
and files fetched from remote URLs.
"""

import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from ..schemas.requests import BatchClassifyRequest, ClassifyRequest, URLClassifyRequest
from ..schemas.responses import BatchResult, ClassificationResult

logger = logging.getLogger("rubyguardian.routes.classify")

router = APIRouter()

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_BATCH_SIZE = 50
URL_FETCH_TIMEOUT = 30.0
ALLOWED_EXTENSIONS = {".rb", ".gemspec", ".rake", ".erb"}


async def _perform_classification(
    content: bytes,
    filename: str,
    model_id: Optional[str] = None,
) -> ClassificationResult:
    """Run the classification pipeline on raw file content."""
    from ...features.extractors import ExtractorRegistry

    file_hash = hashlib.sha256(content).hexdigest()
    source_text = content.decode("utf-8", errors="replace")

    registry = ExtractorRegistry()
    feature_vector = registry.extract_all(source_text)

    # Placeholder for actual model inference; returns mock result
    malicious_probability = min(
        1.0, feature_vector.get("obfuscation_score", 0.0) * 0.4
        + feature_vector.get("entropy", 0.0) / 10.0
        + feature_vector.get("network_call_count", 0) * 0.05
    )
    is_malicious = malicious_probability >= 0.5
    label = "malicious" if is_malicious else "benign"

    return ClassificationResult(
        filename=filename,
        sha256=file_hash,
        label=label,
        confidence=round(malicious_probability if is_malicious else 1.0 - malicious_probability, 4),
        malicious_probability=round(malicious_probability, 4),
        model_id=model_id or "ensemble-v1",
        features=feature_vector,
    )


@router.post("/classify", response_model=ClassificationResult)
async def classify_file(
    file: UploadFile = File(...),
    model_id: Optional[str] = Query(None, description="Specific model to use for classification"),
):
    """Classify a single uploaded Ruby file as benign or malicious."""
    suffix = Path(file.filename or "unknown.rb").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported file type '{suffix}'. Allowed: {ALLOWED_EXTENSIONS}",
        )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {MAX_FILE_SIZE // (1024 * 1024)} MB",
        )

    logger.info("Classifying file %s (%d bytes)", file.filename, len(content))
    result = await _perform_classification(content, file.filename or "unknown.rb", model_id)
    return result


@router.post("/classify/batch", response_model=BatchResult)
async def classify_batch(
    files: list[UploadFile] = File(...),
    model_id: Optional[str] = Query(None, description="Specific model to use"),
):
    """Classify a batch of uploaded Ruby files."""
    if len(files) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {len(files)} exceeds maximum of {MAX_BATCH_SIZE}",
        )

    results = []
    errors = []
    for upload in files:
        try:
            content = await upload.read()
            if len(content) > MAX_FILE_SIZE:
                errors.append({"filename": upload.filename, "error": "File too large"})
                continue
            result = await _perform_classification(content, upload.filename or "unknown.rb", model_id)
            results.append(result)
        except Exception as exc:
            logger.exception("Error classifying %s", upload.filename)
            errors.append({"filename": upload.filename, "error": str(exc)})

    logger.info("Batch classification complete: %d results, %d errors", len(results), len(errors))
    return BatchResult(
        total=len(files),
        classified=len(results),
        failed=len(errors),
        results=results,
        errors=errors,
    )


@router.post("/classify/url", response_model=ClassificationResult)
async def classify_from_url(request: URLClassifyRequest):
    """Fetch a Ruby file from a URL and classify it."""
    logger.info("Fetching file from URL: %s", request.url)
    try:
        async with httpx.AsyncClient(timeout=URL_FETCH_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(str(request.url))
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Remote server returned {exc.response.status_code}",
        )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to fetch URL: {exc}",
        )

    content = response.content
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Fetched content exceeds maximum allowed size",
        )

    filename = Path(str(request.url)).name or "remote_file.rb"
    result = await _perform_classification(content, filename, request.model_id)
    return result
