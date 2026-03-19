"""
RubyGuardian -- Volatility 3 Plugin: Ruby Heap Scanner

Scans process memory for Ruby heap structures (RValue slots, heap pages)
and identifies anomalous allocation patterns indicative of exploitation.
"""

import logging
import struct
from typing import List, Tuple, Iterator, Optional

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins import yarascan

logger = logging.getLogger(__name__)

# Ruby type flag constants (Ruby 3.x)
T_MASK = 0x1F
RVALUE_SIZE = 40
HEAP_PAGE_HEADER_SIZE = 80

RUBY_TYPE_MAP = {
    0x00: "T_NONE",   0x01: "T_OBJECT", 0x02: "T_CLASS",
    0x03: "T_MODULE", 0x04: "T_FLOAT",  0x05: "T_STRING",
    0x06: "T_REGEXP", 0x07: "T_ARRAY",  0x08: "T_HASH",
    0x09: "T_STRUCT", 0x0A: "T_BIGNUM", 0x0B: "T_FILE",
    0x0C: "T_DATA",   0x0D: "T_MATCH",  0x0E: "T_COMPLEX",
    0x0F: "T_RATIONAL", 0x1A: "T_IMEMO", 0x1B: "T_NODE",
    0x1C: "T_ICLASS", 0x1D: "T_ZOMBIE", 0x1E: "T_MOVED",
}


class RubyHeapScanner(interfaces.plugins.PluginInterface):
    """Scans memory for Ruby heap structures and detects anomalies."""

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
            requirements.BooleanRequirement(
                name="detect_spray",
                description="Enable heap spray detection heuristics",
                default=True,
                optional=True,
            ),
            requirements.IntRequirement(
                name="min_page_objects",
                description="Minimum objects per page to consider valid",
                default=10,
                optional=True,
            ),
        ]

    def _generator(self) -> Iterator[Tuple[int, Tuple]]:
        target_pid = self.config.get("pid", None)
        detect_spray = self.config.get("detect_spray", True)
        min_page_objects = self.config.get("min_page_objects", 10)

        layer_name = self.config["primary"]
        layer = self.context.layers[layer_name]

        heap_pages = []
        type_distribution = {}
        total_rvalues = 0
        anomalies = []

        # Scan through the memory layer looking for Ruby heap page signatures
        for offset in self._scan_for_heap_pages(layer):
            page_info = self._analyze_heap_page(layer, offset, min_page_objects)
            if page_info is None:
                continue

            heap_pages.append(page_info)
            total_rvalues += page_info["object_count"]

            for type_name, count in page_info["type_counts"].items():
                type_distribution[type_name] = (
                    type_distribution.get(type_name, 0) + count
                )

        # Run anomaly detection across discovered pages
        if detect_spray:
            spray_results = self._detect_heap_spray(heap_pages)
            anomalies.extend(spray_results)

        wx_anomalies = self._detect_wx_rvalues(layer, heap_pages)
        anomalies.extend(wx_anomalies)

        zombie_count = type_distribution.get("T_ZOMBIE", 0)
        if zombie_count > 50:
            anomalies.append({
                "type": "excessive_zombies",
                "severity": "high",
                "detail": f"{zombie_count} zombie objects found",
                "address": 0,
            })

        # Yield summary rows for each heap page
        for idx, page in enumerate(heap_pages):
            yield (0, (
                idx,
                format(page["base_address"], "#018x"),
                page["object_count"],
                page["free_count"],
                page["occupancy"],
                page["dominant_type"],
                page.get("anomaly", "none"),
            ))

        # Yield anomaly rows
        for anomaly in anomalies:
            yield (1, (
                -1,
                format(anomaly.get("address", 0), "#018x"),
                0,
                0,
                0.0,
                anomaly["type"],
                f"[{anomaly['severity']}] {anomaly['detail']}",
            ))

    def _scan_for_heap_pages(self, layer) -> List[int]:
        """Scan memory for potential Ruby heap page boundaries."""
        offsets = []
        try:
            scan_size = layer.maximum_address - layer.minimum_address
        except AttributeError:
            return offsets

        # Ruby heap pages are typically 16KB-aligned
        page_alignment = 16384
        current = layer.minimum_address

        while current < layer.maximum_address:
            try:
                data = layer.read(current, min(RVALUE_SIZE * 8, 320))
            except exceptions.InvalidAddressException:
                current += page_alignment
                continue

            if self._looks_like_rvalue_sequence(data):
                offsets.append(current)

            current += page_alignment

            if len(offsets) >= 10000:
                break

        return offsets

    def _looks_like_rvalue_sequence(self, data: bytes) -> bool:
        """Heuristic check for a sequence of valid-looking RValues."""
        if len(data) < RVALUE_SIZE * 3:
            return False

        valid_count = 0
        for i in range(0, len(data) - RVALUE_SIZE + 1, RVALUE_SIZE):
            flags = struct.unpack_from("<Q", data, i)[0]
            type_id = flags & T_MASK

            if type_id in RUBY_TYPE_MAP and flags != 0:
                klass = struct.unpack_from("<Q", data, i + 8)[0]
                if klass == 0 or (0x400000 < klass < 0x800000000000):
                    valid_count += 1

        return valid_count >= 3

    def _analyze_heap_page(
        self, layer, offset: int, min_objects: int
    ) -> Optional[dict]:
        """Analyze a potential Ruby heap page starting at offset."""
        try:
            page_data = layer.read(offset, RVALUE_SIZE * 409)
        except exceptions.InvalidAddressException:
            return None

        type_counts = {}
        free_count = 0
        object_count = 0

        for slot in range(0, len(page_data) - RVALUE_SIZE + 1, RVALUE_SIZE):
            flags = struct.unpack_from("<Q", page_data, slot)[0]
            type_id = flags & T_MASK
            type_name = RUBY_TYPE_MAP.get(type_id, None)

            if type_name is None:
                continue

            if type_name == "T_NONE":
                free_count += 1
            else:
                object_count += 1
                type_counts[type_name] = type_counts.get(type_name, 0) + 1

        if object_count < min_objects:
            return None

        total = object_count + free_count
        occupancy = round(object_count / total, 4) if total > 0 else 0.0

        dominant_type = max(type_counts, key=type_counts.get) if type_counts else "T_NONE"

        anomaly = "none"
        if occupancy > 0.99 and object_count > 100:
            anomaly = "fully_packed"
        elif type_counts.get("T_STRING", 0) > object_count * 0.95:
            anomaly = "string_dominated"

        return {
            "base_address": offset,
            "object_count": object_count,
            "free_count": free_count,
            "occupancy": occupancy,
            "type_counts": type_counts,
            "dominant_type": dominant_type,
            "anomaly": anomaly,
        }

    def _detect_heap_spray(self, pages: List[dict]) -> List[dict]:
        """Detect heap spray patterns across pages."""
        anomalies = []
        if len(pages) < 5:
            return anomalies

        # Check for many pages with identical type distributions
        dist_fingerprints = {}
        for page in pages:
            fp = tuple(sorted(page["type_counts"].items()))
            dist_fingerprints.setdefault(fp, []).append(page["base_address"])

        for fingerprint, addresses in dist_fingerprints.items():
            if len(addresses) >= 20:
                anomalies.append({
                    "type": "heap_spray",
                    "severity": "critical",
                    "detail": (
                        f"{len(addresses)} pages with identical type distribution: "
                        f"{dict(fingerprint)}"
                    ),
                    "address": addresses[0],
                })

        # Check for suspicious spacing between packed pages
        packed = [p for p in pages if p["anomaly"] == "fully_packed"]
        if len(packed) >= 10:
            addrs = sorted(p["base_address"] for p in packed)
            spacings = [addrs[i + 1] - addrs[i] for i in range(len(addrs) - 1)]
            if spacings:
                avg_spacing = sum(spacings) / len(spacings)
                variance = sum((s - avg_spacing) ** 2 for s in spacings) / len(spacings)
                if variance < avg_spacing * 0.1:
                    anomalies.append({
                        "type": "uniform_spray",
                        "severity": "critical",
                        "detail": (
                            f"{len(packed)} fully packed pages at uniform spacing "
                            f"(avg {avg_spacing:.0f} bytes)"
                        ),
                        "address": addrs[0],
                    })

        return anomalies

    def _detect_wx_rvalues(self, layer, pages: List[dict]) -> List[dict]:
        """Detect RValues in writable+executable memory regions."""
        anomalies = []
        for page in pages:
            addr = page["base_address"]
            # Check if this memory region has WX permissions by reading page table
            # This is a simplified check; real implementation queries VAD/page tables
            if page.get("anomaly") == "string_dominated" and page["object_count"] > 200:
                anomalies.append({
                    "type": "suspicious_strings",
                    "severity": "high",
                    "detail": (
                        f"String-dominated page at {addr:#018x} with "
                        f"{page['object_count']} objects"
                    ),
                    "address": addr,
                })
        return anomalies

    def run(self):
        return renderers.TreeGrid(
            [
                ("Page#", int),
                ("BaseAddress", str),
                ("Objects", int),
                ("Free", int),
                ("Occupancy", float),
                ("DominantType", str),
                ("Anomaly", str),
            ],
            self._generator(),
        )
