"""
Network-related feature extractor for Ruby scripts.

Extracts features related to network activity by analyzing source code
for network API usage, hardcoded endpoints, protocol patterns, and
data transfer indicators that may signal malicious communication.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import yaml
from loguru import logger


@dataclass
class NetworkFeatures:
    """Container for network-related features."""

    unique_destination_ips: int = 0
    unique_destination_ports: int = 0
    dns_query_count: int = 0
    connection_frequency: int = 0
    data_transfer_volume_indicator: int = 0
    non_standard_port_usage: int = 0
    encrypted_traffic_indicator: int = 0
    raw_socket_usage: int = 0
    http_request_count: int = 0
    socket_creation_count: int = 0
    network_api_diversity: float = 0.0
    external_communication_score: float = 0.0

    def to_dict(self) -> dict:
        """Convert to a flat dictionary with prefixed keys."""
        return {
            "net_unique_destination_ips": self.unique_destination_ips,
            "net_unique_destination_ports": self.unique_destination_ports,
            "net_dns_query_count": self.dns_query_count,
            "net_connection_frequency": self.connection_frequency,
            "net_data_transfer_volume_indicator": self.data_transfer_volume_indicator,
            "net_non_standard_port_usage": self.non_standard_port_usage,
            "net_encrypted_traffic_indicator": self.encrypted_traffic_indicator,
            "net_raw_socket_usage": self.raw_socket_usage,
            "net_http_request_count": self.http_request_count,
            "net_socket_creation_count": self.socket_creation_count,
            "net_network_api_diversity": self.network_api_diversity,
            "net_external_communication_score": self.external_communication_score,
        }

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array(list(self.to_dict().values()), dtype=np.float64)


class NetworkFeatureExtractor:
    """Extracts network-related features from Ruby source code.

    Performs static analysis to identify network communication patterns,
    hardcoded endpoints, protocol usage, and suspicious network behaviors
    commonly found in malware such as C2 communication, data exfiltration,
    and reverse shells.
    """

    # IP address pattern (IPv4)
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )

    # Port number pattern (in connection context)
    PORT_PATTERN = re.compile(
        r'(?:port|:\s*|,\s*)(\d{2,5})\b'
    )

    # Standard ports that are less suspicious
    STANDARD_PORTS = {80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 993, 995}

    # DNS resolution patterns
    DNS_PATTERNS = re.compile(
        r'(?:Resolv\.getaddress|Resolv\.getname|'
        r'Socket\.gethostbyname|Addrinfo\.getaddrinfo|'
        r'resolve|dns_lookup|nslookup)',
        re.MULTILINE,
    )

    # Socket creation patterns
    SOCKET_PATTERNS = re.compile(
        r'(?:TCPSocket\.(?:new|open)|UDPSocket\.(?:new|open)|'
        r'Socket\.(?:new|pair|tcp|udp)|'
        r'TCPServer\.(?:new|open)|UNIXSocket\.new)',
        re.MULTILINE,
    )

    # Raw socket patterns (more suspicious)
    RAW_SOCKET_PATTERNS = re.compile(
        r'(?:Socket\.new\s*\(\s*(?::INET|Socket::AF_INET)\s*,\s*'
        r'(?::RAW|Socket::SOCK_RAW)|'
        r'BasicSocket|RawSocket)',
        re.MULTILINE,
    )

    # HTTP request patterns
    HTTP_PATTERNS = re.compile(
        r'(?:Net::HTTP\.(?:get|post|put|delete|start|new)|'
        r'HTTParty\.(?:get|post|put|delete)|'
        r'RestClient\.(?:get|post|put|delete)|'
        r'Faraday\.(?:get|post|put|delete)|'
        r'open-uri|URI\.open|Curl|Typhoeus|'
        r'\.(?:get|post|put|delete|patch)\s*\(\s*["\x27]http)',
        re.MULTILINE,
    )

    # Encrypted communication indicators
    ENCRYPTED_PATTERNS = re.compile(
        r'(?:OpenSSL|ssl|https|TLS|SSLSocket|'
        r'Net::HTTPS|SSL_VERIFY|VERIFY_PEER)',
        re.MULTILINE | re.IGNORECASE,
    )

    # Data transfer patterns (large data movement indicators)
    DATA_TRANSFER_PATTERNS = re.compile(
        r'(?:\.(?:write|send|sendmsg|puts)\s*\(|'
        r'upload|exfil|transmit|transfer|'
        r'IO\.copy_stream|\.(?:read|recv|recvmsg)\s*\()',
        re.MULTILINE,
    )

    # Network API categories for diversity calculation
    NETWORK_API_CATEGORIES = {
        "tcp": re.compile(r'TCPSocket|TCPServer', re.MULTILINE),
        "udp": re.compile(r'UDPSocket', re.MULTILINE),
        "http": re.compile(r'Net::HTTP|HTTParty|RestClient|Faraday', re.MULTILINE),
        "socket": re.compile(r'Socket\.new|BasicSocket', re.MULTILINE),
        "dns": re.compile(r'Resolv|gethostbyname|getaddrinfo', re.MULTILINE),
        "ssl": re.compile(r'OpenSSL|SSLSocket|HTTPS', re.MULTILINE | re.IGNORECASE),
        "uri": re.compile(r'URI\.open|open-uri|URI\.parse', re.MULTILINE),
    }

    # Scoring weights for external communication score
    COMMUNICATION_WEIGHTS = {
        "ip_count": 2.0,
        "port_count": 1.5,
        "socket_count": 2.0,
        "http_count": 1.0,
        "dns_count": 1.5,
        "raw_socket": 3.0,
        "non_standard_port": 2.5,
        "data_transfer": 1.5,
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
    ) -> None:
        """Initialize the network feature extractor.

        Args:
            config_path: Optional path to feature config YAML.
        """
        if config_path:
            self._load_config(config_path)

        logger.debug("NetworkFeatureExtractor initialized")

    def _load_config(self, config_path: str | Path) -> None:
        """Load network feature settings from YAML config.

        Args:
            config_path: Path to the feature configuration file.
        """
        path = Path(config_path)
        if not path.exists():
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        # Configuration can extend standard ports or adjust weights
        net_config = config.get("network_features", {})
        extra_standard_ports = net_config.get("extra_standard_ports", [])
        self.STANDARD_PORTS.update(extra_standard_ports)

    def extract(self, source_code: str) -> NetworkFeatures:
        """Extract network-related features from Ruby source code.

        Args:
            source_code: Raw Ruby source code.

        Returns:
            NetworkFeatures with all computed metrics.
        """
        features = NetworkFeatures()

        if not source_code:
            return features

        # Unique destination IPs
        ip_matches = set(self.IP_PATTERN.findall(source_code))
        # Filter out common non-routable addresses
        external_ips = {
            ip for ip in ip_matches
            if not ip.startswith("127.") and not ip.startswith("0.")
        }
        features.unique_destination_ips = len(external_ips)

        # Port analysis
        port_matches = self.PORT_PATTERN.findall(source_code)
        ports = set()
        non_standard_count = 0
        for port_str in port_matches:
            try:
                port = int(port_str)
                if 1 <= port <= 65535:
                    ports.add(port)
                    if port not in self.STANDARD_PORTS:
                        non_standard_count += 1
            except ValueError:
                continue
        features.unique_destination_ports = len(ports)
        features.non_standard_port_usage = non_standard_count

        # DNS queries
        features.dns_query_count = len(self.DNS_PATTERNS.findall(source_code))

        # Socket creation
        features.socket_creation_count = len(
            self.SOCKET_PATTERNS.findall(source_code)
        )

        # Connection frequency (total network-related API calls)
        features.connection_frequency = (
            features.socket_creation_count
            + features.dns_query_count
        )

        # Raw socket usage
        features.raw_socket_usage = len(
            self.RAW_SOCKET_PATTERNS.findall(source_code)
        )

        # HTTP requests
        features.http_request_count = len(
            self.HTTP_PATTERNS.findall(source_code)
        )
        features.connection_frequency += features.http_request_count

        # Encrypted traffic
        features.encrypted_traffic_indicator = min(
            len(self.ENCRYPTED_PATTERNS.findall(source_code)), 10
        )

        # Data transfer volume indicator
        features.data_transfer_volume_indicator = min(
            len(self.DATA_TRANSFER_PATTERNS.findall(source_code)), 20
        )

        # Network API diversity
        apis_used = 0
        for _category, pattern in self.NETWORK_API_CATEGORIES.items():
            if pattern.search(source_code):
                apis_used += 1
        features.network_api_diversity = (
            apis_used / len(self.NETWORK_API_CATEGORIES)
            if self.NETWORK_API_CATEGORIES else 0.0
        )

        # External communication score (weighted composite)
        features.external_communication_score = self._compute_communication_score(
            features
        )

        logger.debug(
            "Network features: ips={}, ports={}, sockets={}, score={:.2f}",
            features.unique_destination_ips,
            features.unique_destination_ports,
            features.socket_creation_count,
            features.external_communication_score,
        )
        return features

    def extract_from_file(self, file_path: str | Path) -> NetworkFeatures:
        """Extract network features from a Ruby source file.

        Args:
            file_path: Path to the Ruby source file.

        Returns:
            NetworkFeatures dataclass.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ruby file not found: {path}")
        source_code = path.read_text(encoding="utf-8", errors="replace")
        return self.extract(source_code)

    def _compute_communication_score(self, features: NetworkFeatures) -> float:
        """Compute a weighted external communication suspicion score.

        Higher scores indicate more network activity and potentially
        suspicious communication patterns.

        Args:
            features: Partially populated NetworkFeatures.

        Returns:
            Normalized score between 0.0 and 1.0.
        """
        raw_score = (
            features.unique_destination_ips * self.COMMUNICATION_WEIGHTS["ip_count"]
            + features.unique_destination_ports * self.COMMUNICATION_WEIGHTS["port_count"]
            + features.socket_creation_count * self.COMMUNICATION_WEIGHTS["socket_count"]
            + features.http_request_count * self.COMMUNICATION_WEIGHTS["http_count"]
            + features.dns_query_count * self.COMMUNICATION_WEIGHTS["dns_count"]
            + features.raw_socket_usage * self.COMMUNICATION_WEIGHTS["raw_socket"]
            + features.non_standard_port_usage * self.COMMUNICATION_WEIGHTS["non_standard_port"]
            + features.data_transfer_volume_indicator * self.COMMUNICATION_WEIGHTS["data_transfer"]
        )

        # Sigmoid normalization to [0, 1]
        normalized = 1.0 / (1.0 + np.exp(-0.5 * (raw_score - 10.0)))
        return float(normalized)
