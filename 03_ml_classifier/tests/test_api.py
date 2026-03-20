"""
Integration tests for the RubyGuardian Classifier API endpoints.

Tests cover classification (single, batch, URL), health checks,
and model management routes.
"""

import io
from unittest.mock import AsyncMock, patch

import pytest


class TestHealthEndpoints:
    """Tests for /api/v1/health, /ready, and /live endpoints."""

    def test_health_returns_200(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("healthy", "degraded")
        assert "uptime_seconds" in data
        assert "version" in data
        assert "checks" in data

    def test_health_contains_subsystem_checks(self, client):
        data = client.get("/api/v1/health").json()
        assert "model_registry" in data["checks"]
        assert "feature_pipeline" in data["checks"]
        assert "disk_space" in data["checks"]

    def test_readiness_returns_200_when_ready(self, client):
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 200
        assert response.json()["ready"] is True

    def test_liveness_returns_200(self, client):
        response = client.get("/api/v1/health/live")
        assert response.status_code == 200
        assert response.json()["alive"] is True

    def test_liveness_includes_uptime(self, client):
        data = client.get("/api/v1/health/live").json()
        assert "uptime_seconds" in data
        assert data["uptime_seconds"] >= 0


class TestClassifyEndpoints:
    """Tests for /api/v1/classify endpoints."""

    def test_classify_single_file(self, client, sample_ruby_file):
        with open(sample_ruby_file, "rb") as f:
            response = client.post(
                "/api/v1/classify",
                files={"file": ("greeter.rb", f, "application/octet-stream")},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["label"] in ("benign", "malicious")
        assert "sha256" in data
        assert len(data["sha256"]) == 64
        assert 0.0 <= data["confidence"] <= 1.0
        assert data["model_id"] is not None

    def test_classify_rejects_non_ruby_file(self, client):
        content = b"print('hello world')"
        response = client.post(
            "/api/v1/classify",
            files={"file": ("script.py", io.BytesIO(content), "application/octet-stream")},
        )
        assert response.status_code == 415

    def test_classify_rejects_oversized_file(self, client):
        big_content = b"x" * (11 * 1024 * 1024)
        response = client.post(
            "/api/v1/classify",
            files={"file": ("big.rb", io.BytesIO(big_content), "application/octet-stream")},
        )
        assert response.status_code == 413

    def test_classify_batch(self, client, sample_ruby_file, malicious_ruby_file):
        files = []
        for path in [sample_ruby_file, malicious_ruby_file]:
            with open(path, "rb") as f:
                files.append(("files", (path.name, f.read(), "application/octet-stream")))

        response = client.post("/api/v1/classify/batch", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert data["classified"] + data["failed"] == data["total"]
        assert len(data["results"]) == data["classified"]

    def test_classify_batch_rejects_too_many_files(self, client):
        files = [
            ("files", (f"file_{i}.rb", b"puts 'hi'", "application/octet-stream"))
            for i in range(51)
        ]
        response = client.post("/api/v1/classify/batch", files=files)
        assert response.status_code == 400

    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    def test_classify_url(self, mock_get, client):
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.content = b"puts 'hello from url'"
        mock_response.raise_for_status = lambda: None
        mock_get.return_value = mock_response

        response = client.post(
            "/api/v1/classify/url",
            json={"url": "https://example.com/script.rb"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "label" in data

    def test_classify_url_invalid_url(self, client):
        response = client.post(
            "/api/v1/classify/url",
            json={"url": "not-a-valid-url"},
        )
        assert response.status_code == 422


class TestModelEndpoints:
    """Tests for /api/v1/models endpoints."""

    def test_list_models(self, client):
        response = client.get("/api/v1/models")
        assert response.status_code == 200
        models = response.json()
        assert isinstance(models, list)
        assert len(models) >= 1
        for model in models:
            assert "id" in model
            assert "name" in model
            assert "version" in model

    def test_list_models_loaded_only(self, client):
        response = client.get("/api/v1/models?loaded_only=true")
        assert response.status_code == 200
        for model in response.json():
            assert model["loaded"] is True

    def test_get_model_info(self, client):
        response = client.get("/api/v1/models/ensemble-v1/info")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "ensemble-v1"
        assert "metrics" in data
        assert "accuracy" in data["metrics"]

    def test_get_model_info_not_found(self, client):
        response = client.get("/api/v1/models/nonexistent/info")
        assert response.status_code == 404

    def test_reload_model(self, client):
        response = client.post("/api/v1/models/ensemble-v1/reload")
        assert response.status_code == 200
        data = response.json()
        assert data["loaded"] is True
        assert data["loaded_at"] is not None

    def test_reload_nonexistent_model(self, client):
        response = client.post("/api/v1/models/nonexistent/reload")
        assert response.status_code == 404
