"""
RubyGuardian -- Volatility 3 Plugin: Ruby String Extractor

Extracts Ruby String objects (T_STRING RValues) from process memory,
reconstructing both embedded and heap-allocated string contents. Classifies
strings by forensic relevance and detects obfuscated payloads.
"""

import base64
import hashlib
import logging
import math
import re
import struct
from typing import List, Tuple, Iterator, Optional

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements

logger = logging.getLogger(__name__)

T_STRING = 0x05
T_MASK = 0x1F
RVALUE_SIZE = 40
STR_NOEMBED = 1 << 13
STR_SHARED = 1 << 14
EMBED_LEN_MASK = 0x1F0000
EMBED_LEN_SHIFT = 16
MAX_SANE_LENGTH = 10 * 1024 * 1024  # 10 MB

# Classification patterns for extracted strings
CLASSIFICATION_RULES = [
    {
        "name": "url",
        "pattern": re.compile(rb"https?://[^\x00\s]{4,}", re.IGNORECASE),
        "severity": "medium",
        "category": "network",
    },
    {
        "name": "ipv4_port",
        "pattern": re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}"),
        "severity": "medium",
        "category": "network",
    },
    {
        "name": "private_key",
        "pattern": re.compile(rb"BEGIN (?:RSA |DSA |EC )?PRIVATE KEY"),
        "severity": "critical",
        "category": "credential",
    },
    {
        "name": "aws_key",
        "pattern": re.compile(rb"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
        "category": "credential",
    },
    {
        "name": "jwt_token",
        "pattern": re.compile(rb"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+"),
        "severity": "high",
        "category": "credential",
    },
    {
        "name": "eval_pattern",
        "pattern": re.compile(rb"eval\s*\(.*(?:Base64|decode|Marshal)", re.DOTALL),
        "severity": "critical",
        "category": "code_execution",
    },
    {
        "name": "shell_command",
        "pattern": re.compile(
            rb"(?:system|exec|spawn)\s*\(.*(?:bash|sh|curl|wget|nc)\b", re.DOTALL
        ),
        "severity": "critical",
        "category": "code_execution",
    },
    {
        "name": "reverse_shell",
        "pattern": re.compile(rb"TCPSocket\.(?:new|open)\s*\(", re.IGNORECASE),
        "severity": "critical",
        "category": "code_execution",
    },
    {
        "name": "file_path_sensitive",
        "pattern": re.compile(
            rb"/(?:etc/(?:passwd|shadow|sudoers)|proc/self|dev/shm/)"
        ),
        "severity": "high",
        "category": "filesystem",
    },
    {
        "name": "crypto_mining",
        "pattern": re.compile(
            rb"(?:stratum\+tcp|xmrig|monero|cryptonight|hashrate)", re.IGNORECASE
        ),
        "severity": "critical",
        "category": "malware",
    },
    {
        "name": "base64_payload",
        "pattern": re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}"),
        "severity": "medium",
        "category": "encoded",
    },
    {
        "name": "sql_injection",
        "pattern": re.compile(
            rb"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE)", re.IGNORECASE
        ),
        "severity": "high",
        "category": "injection",
    },
]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = float(len(data))
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values() if c > 0
    )


class ExtractedRubyString:
    """Holds a single extracted Ruby string with metadata."""

    __slots__ = [
        "address", "value", "length", "encoding_flag",
        "is_embedded", "is_shared", "frozen",
        "entropy", "classifications", "sha256",
    ]

    def __init__(self, address: int, value: bytes, flags: int):
        self.address = address
        self.value = value
        self.length = len(value)
        self.is_embedded = not bool(flags & STR_NOEMBED)
        self.is_shared = bool(flags & STR_SHARED)
        self.frozen = bool(flags & (1 << 11))
        self.encoding_flag = (flags >> 22) & 0x1F
        self.entropy = calculate_entropy(value)
        self.classifications = []
        self.sha256 = hashlib.sha256(value).hexdigest()

    @property
    def text(self) -> str:
        try:
            return self.value.decode("utf-8", errors="replace")
        except Exception:
            return self.value.hex()

    def classify(self) -> None:
        """Run classification rules against the string content."""
        for rule in CLASSIFICATION_RULES:
            if rule["pattern"].search(self.value):
                self.classifications.append({
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                })

    def is_suspicious(self) -> bool:
        return (
            len(self.classifications) > 0
            or (self.entropy > 6.0 and self.length > 64)
        )


class RubyStringExtractor(interfaces.plugins.PluginInterface):
    """Extracts and classifies Ruby String objects from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer to scan",
                architectures=["Intel64"],
            ),
            requirements.SymbolTableRequirement(
                name="vmlinux",
                description="Linux kernel symbol table",
            ),
            requirements.IntRequirement(
                name="pid",
                description="Target Ruby process PID",
                optional=True,
            ),
            requirements.IntRequirement(
                name="min_length",
                description="Minimum string length to extract",
                default=4,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="suspicious_only",
                description="Only show suspicious/classified strings",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="output_file",
                description="Path to write extracted strings as JSON",
                optional=True,
            ),
            requirements.StringRequirement(
                name="category_filter",
                description="Only show strings matching this category",
                optional=True,
            ),
        ]

    def _generator(self) -> Iterator[Tuple[int, Tuple]]:
        layer_name = self.config["primary"]
        layer = self.context.layers[layer_name]
        min_length = self.config.get("min_length", 4)
        suspicious_only = self.config.get("suspicious_only", False)
        category_filter = self.config.get("category_filter", None)

        extracted = []
        stats = {
            "total": 0, "suspicious": 0,
            "by_category": {}, "high_entropy": 0,
        }

        for ruby_str in self._scan_for_strings(layer, min_length):
            ruby_str.classify()

            if category_filter:
                cats = [c["category"] for c in ruby_str.classifications]
                if category_filter not in cats:
                    continue

            if suspicious_only and not ruby_str.is_suspicious():
                continue

            extracted.append(ruby_str)
            stats["total"] += 1

            if ruby_str.is_suspicious():
                stats["suspicious"] += 1

            if ruby_str.entropy > 6.0:
                stats["high_entropy"] += 1

            for cls in ruby_str.classifications:
                cat = cls["category"]
                stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        # Sort by severity: critical first, then by entropy
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        extracted.sort(
            key=lambda s: (
                min(
                    (severity_order.get(c["severity"], 99)
                     for c in s.classifications),
                    default=99,
                ),
                -s.entropy,
            )
        )

        output_path = self.config.get("output_file", None)
        if output_path:
            self._write_output(output_path, extracted, stats)

        for idx, s in enumerate(extracted):
            classifications_str = ", ".join(
                f"{c['name']}({c['severity']})" for c in s.classifications
            ) or "none"

            yield (0, (
                f"0x{s.address:016x}",
                s.length,
                round(s.entropy, 3),
                "embed" if s.is_embedded else "heap",
                s.frozen,
                classifications_str,
                s.text[:100],
            ))

    def _scan_for_strings(
        self, layer, min_length: int
    ) -> Iterator[ExtractedRubyString]:
        """Scan memory for T_STRING RValues and extract contents."""
        page_size = 16384
        current = layer.minimum_address
        count = 0
        max_strings = 200000

        while current < layer.maximum_address and count < max_strings:
            try:
                chunk = layer.read(current, page_size)
            except exceptions.InvalidAddressException:
                current += page_size
                continue

            offset = 0
            while offset + RVALUE_SIZE <= len(chunk) and count < max_strings:
                flags = struct.unpack_from("<Q", chunk, offset)[0]
                type_id = flags & T_MASK

                if type_id == T_STRING and flags != 0:
                    addr = current + offset
                    raw = chunk[offset: offset + RVALUE_SIZE]
                    value = self._read_string_value(layer, raw, flags)

                    if value and len(value) >= min_length:
                        ruby_str = ExtractedRubyString(addr, value, flags)
                        count += 1
                        yield ruby_str

                offset += RVALUE_SIZE

            current += page_size

    def _read_string_value(
        self, layer, raw: bytes, flags: int
    ) -> Optional[bytes]:
        """Read the actual string bytes from an RValue."""
        if flags & STR_NOEMBED:
            # Heap-allocated string: length at +16, pointer at +24
            str_len = struct.unpack_from("<q", raw, 16)[0]
            str_ptr = struct.unpack_from("<Q", raw, 24)[0]

            if str_len <= 0 or str_len > MAX_SANE_LENGTH or str_ptr == 0:
                return None
            if str_ptr < 0x400000 or str_ptr > 0x800000000000:
                return None

            read_len = min(str_len, 65536)
            try:
                return layer.read(str_ptr, read_len)
            except exceptions.InvalidAddressException:
                return None
        else:
            # Embedded string: length encoded in flags, data starts at +16
            embed_len = (flags & EMBED_LEN_MASK) >> EMBED_LEN_SHIFT
            if embed_len <= 0 or embed_len > 24:
                return None
            return raw[16: 16 + embed_len]

    def _try_decode_base64(self, data: bytes) -> Optional[bytes]:
        """Attempt to decode base64 content for deeper inspection."""
        try:
            text = data.decode("ascii", errors="strict")
            decoded = base64.b64decode(text, validate=True)
            if len(decoded) > 4:
                return decoded
        except Exception:
            pass
        return None

    def _write_output(
        self,
        path: str,
        strings: List[ExtractedRubyString],
        stats: dict,
    ) -> None:
        """Write extracted strings to a JSON file."""
        import json

        output = {
            "metadata": {
                "plugin": "RubyStringExtractor",
                "version": "1.0.0",
                "stats": stats,
            },
            "strings": [
                {
                    "address": f"0x{s.address:016x}",
                    "length": s.length,
                    "entropy": round(s.entropy, 4),
                    "sha256": s.sha256,
                    "embedded": s.is_embedded,
                    "shared": s.is_shared,
                    "frozen": s.frozen,
                    "classifications": s.classifications,
                    "value": s.text[:500],
                }
                for s in strings
            ],
        }

        with open(path, "w") as f:
            json.dump(output, f, indent=2)

        logger.info("Wrote %d strings to %s", len(strings), path)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", str),
                ("Length", int),
                ("Entropy", float),
                ("Storage", str),
                ("Frozen", bool),
                ("Classifications", str),
                ("Preview", str),
            ],
            self._generator(),
        )
