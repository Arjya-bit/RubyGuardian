"""
Unit tests for the RubyGuardian feature extraction pipeline.

Covers AST extraction, entropy calculation, and behavioral analysis
of Ruby source code.
"""

import math

import pytest

from ml_classifier.features.extractors.ast_extractor import ASTFeatureExtractor
from ml_classifier.features.extractors.behavioral_extractor import BehavioralFeatureExtractor
from ml_classifier.features.extractors.entropy_extractor import EntropyFeatureExtractor


class TestASTFeatureExtractor:
    """Tests for the AST-based feature extractor."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.extractor = ASTFeatureExtractor()

    def test_extracts_node_count(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "ast_node_count" in features
        assert features["ast_node_count"] > 0

    def test_extracts_max_depth(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "ast_max_depth" in features
        assert features["ast_max_depth"] >= 1

    def test_extracts_complexity(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "cyclomatic_complexity" in features
        assert features["cyclomatic_complexity"] >= 1

    def test_method_count(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "method_def_count" in features
        assert features["method_def_count"] >= 1  # at least 'greet' and 'initialize'

    def test_class_count(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "class_def_count" in features
        assert features["class_def_count"] == 1

    def test_empty_source_returns_zero_nodes(self):
        features = self.extractor.extract("")
        assert features["ast_node_count"] == 0

    def test_malicious_has_higher_complexity(self, benign_ruby_source, malicious_ruby_source):
        benign_features = self.extractor.extract(benign_ruby_source)
        malicious_features = self.extractor.extract(malicious_ruby_source)
        # Malicious scripts with IO.popen and loops tend to have higher complexity
        assert malicious_features["cyclomatic_complexity"] >= benign_features["cyclomatic_complexity"]


class TestEntropyFeatureExtractor:
    """Tests for the entropy feature extractor."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.extractor = EntropyFeatureExtractor()

    def test_extracts_shannon_entropy(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "entropy" in features
        assert 0.0 <= features["entropy"] <= 8.0

    def test_high_entropy_for_obfuscated(self, obfuscated_ruby_source):
        features = self.extractor.extract(obfuscated_ruby_source)
        assert features["entropy"] > 3.5

    def test_max_entropy_for_random_bytes(self):
        # Near-uniform distribution should have entropy close to 8.0
        random_like = bytes(range(256)) * 100
        features = self.extractor.extract(random_like.decode("latin-1"))
        assert features["entropy"] > 7.5

    def test_zero_entropy_for_single_char(self):
        features = self.extractor.extract("aaaaaaaaaa")
        assert features["entropy"] == pytest.approx(0.0, abs=0.01)

    def test_byte_distribution_uniformity(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "byte_distribution_uniformity" in features
        assert 0.0 <= features["byte_distribution_uniformity"] <= 1.0

    def test_encoding_detection(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "detected_encoding" in features

    def test_printable_ratio(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert "printable_ratio" in features
        assert features["printable_ratio"] > 0.9  # normal Ruby code is mostly printable


class TestBehavioralFeatureExtractor:
    """Tests for the behavioral feature extractor."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.extractor = BehavioralFeatureExtractor()

    def test_detects_network_calls(self, malicious_ruby_source):
        features = self.extractor.extract(malicious_ruby_source)
        assert "network_call_count" in features
        assert features["network_call_count"] > 0

    def test_benign_has_no_network_calls(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert features["network_call_count"] == 0

    def test_detects_eval_usage(self, malicious_ruby_source):
        features = self.extractor.extract(malicious_ruby_source)
        assert "eval_count" in features
        assert features["eval_count"] >= 1

    def test_detects_file_operations(self):
        source = "File.open('/etc/passwd', 'r') { |f| puts f.read }\nFile.delete('/tmp/log')\n"
        features = self.extractor.extract(source)
        assert features["file_op_count"] >= 2

    def test_obfuscation_score(self, obfuscated_ruby_source):
        features = self.extractor.extract(obfuscated_ruby_source)
        assert "obfuscation_score" in features
        assert features["obfuscation_score"] > 0.3

    def test_benign_low_obfuscation(self, benign_ruby_source):
        features = self.extractor.extract(benign_ruby_source)
        assert features["obfuscation_score"] < 0.3

    def test_detects_require_statements(self, malicious_ruby_source):
        features = self.extractor.extract(malicious_ruby_source)
        assert "require_count" in features
        assert features["require_count"] >= 2

    def test_detects_socket_usage(self, malicious_ruby_source):
        features = self.extractor.extract(malicious_ruby_source)
        assert features["network_call_count"] >= 2  # net/http + TCPSocket

    def test_combined_risk_indicators(self, malicious_ruby_source):
        features = self.extractor.extract(malicious_ruby_source)
        # Malicious script should have multiple risk indicators
        risk_count = sum([
            features.get("eval_count", 0) > 0,
            features.get("network_call_count", 0) > 0,
            features.get("obfuscation_score", 0) > 0.2,
        ])
        assert risk_count >= 2
