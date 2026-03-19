"""
RubyGuardian -- Volatility 3 Plugin: Ruby ObjectSpace Dump

Reconstructs the Ruby ObjectSpace from a memory image by locating the
Ruby VM's internal heap list and walking all live objects. Produces a
JSON-compatible dump similar to ObjectSpace.dump_all.
"""

import json
import logging
import struct
from typing import List, Tuple, Iterator, Optional, Dict

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements

logger = logging.getLogger(__name__)

T_MASK = 0x1F
RVALUE_SIZE = 40
POINTER_SIZE = 8

RUBY_TYPES = {
    0x00: "NONE",   0x01: "OBJECT", 0x02: "CLASS",  0x03: "MODULE",
    0x04: "FLOAT",  0x05: "STRING", 0x06: "REGEXP", 0x07: "ARRAY",
    0x08: "HASH",   0x09: "STRUCT", 0x0A: "BIGNUM", 0x0B: "FILE",
    0x0C: "DATA",   0x0D: "MATCH",  0x0E: "COMPLEX", 0x0F: "RATIONAL",
    0x1A: "IMEMO",  0x1B: "NODE",   0x1C: "ICLASS", 0x1D: "ZOMBIE",
    0x1E: "MOVED",
}

# Flag bit offsets for common Ruby flags
FL_FREEZE = 1 << 11
FL_EXIVAR = 1 << 12
STR_NOEMBED = 1 << 13


class RubyObjectEntry:
    """Represents a single Ruby object reconstructed from memory."""

    __slots__ = [
        "address", "type_name", "flags", "klass_ptr",
        "frozen", "has_ivars", "size_estimate", "references",
        "value_preview",
    ]

    def __init__(self, address: int, type_name: str, flags: int, klass_ptr: int):
        self.address = address
        self.type_name = type_name
        self.flags = flags
        self.klass_ptr = klass_ptr
        self.frozen = bool(flags & FL_FREEZE)
        self.has_ivars = bool(flags & FL_EXIVAR)
        self.size_estimate = RVALUE_SIZE
        self.references = []
        self.value_preview = ""

    def to_dict(self) -> dict:
        return {
            "address": f"0x{self.address:016x}",
            "type": self.type_name,
            "class": f"0x{self.klass_ptr:016x}",
            "frozen": self.frozen,
            "size": self.size_estimate,
            "references": [f"0x{r:016x}" for r in self.references],
            "preview": self.value_preview,
        }


class RubyObjectSpaceDump(interfaces.plugins.PluginInterface):
    """Reconstructs Ruby ObjectSpace from memory dump."""

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
            requirements.StringRequirement(
                name="output_json",
                description="Path to write JSON ObjectSpace dump",
                optional=True,
            ),
            requirements.ListRequirement(
                name="types",
                element_type=requirements.StringRequirement,
                description="Filter by type names (e.g., STRING,ARRAY)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="max_objects",
                description="Maximum number of objects to dump",
                default=100000,
                optional=True,
            ),
        ]

    def _generator(self) -> Iterator[Tuple[int, Tuple]]:
        layer_name = self.config["primary"]
        layer = self.context.layers[layer_name]
        max_objects = self.config.get("max_objects", 100000)
        type_filter = self.config.get("types", None)

        if type_filter:
            type_filter = set(t.upper() for t in type_filter)

        objects = []
        class_name_cache: Dict[int, str] = {}
        stats = {"total": 0, "by_type": {}, "hidden_candidates": 0}

        # Walk memory looking for valid RValue slots
        for entry in self._walk_rvalues(layer, max_objects):
            if type_filter and entry.type_name not in type_filter:
                continue

            self._extract_value_preview(layer, entry)
            self._extract_references(layer, entry)
            objects.append(entry)

            stats["total"] += 1
            stats["by_type"][entry.type_name] = (
                stats["by_type"].get(entry.type_name, 0) + 1
            )

        # Detect hidden objects (valid RValues in unexpected memory regions)
        hidden = self._find_hidden_objects(layer, objects)
        stats["hidden_candidates"] = len(hidden)
        objects.extend(hidden)

        # Write JSON output if requested
        output_path = self.config.get("output_json", None)
        if output_path:
            self._write_json_dump(output_path, objects, stats)

        # Yield rows for each object
        for idx, obj in enumerate(objects):
            class_label = class_name_cache.get(obj.klass_ptr, "")
            if not class_label and obj.klass_ptr != 0:
                class_label = self._resolve_class_name(layer, obj.klass_ptr)
                class_name_cache[obj.klass_ptr] = class_label

            yield (0, (
                f"0x{obj.address:016x}",
                obj.type_name,
                class_label or f"0x{obj.klass_ptr:016x}",
                obj.frozen,
                obj.size_estimate,
                len(obj.references),
                obj.value_preview[:80],
            ))

    def _walk_rvalues(
        self, layer, max_objects: int
    ) -> Iterator[RubyObjectEntry]:
        """Iterate through memory finding valid Ruby RValue structures."""
        count = 0
        page_size = 16384
        current = layer.minimum_address

        while current < layer.maximum_address and count < max_objects:
            try:
                chunk = layer.read(current, page_size)
            except exceptions.InvalidAddressException:
                current += page_size
                continue

            offset = 0
            while offset + RVALUE_SIZE <= len(chunk) and count < max_objects:
                flags = struct.unpack_from("<Q", chunk, offset)[0]
                type_id = flags & T_MASK

                if type_id in RUBY_TYPES and flags != 0 and type_id != 0x00:
                    klass = struct.unpack_from("<Q", chunk, offset + 8)[0]
                    if self._plausible_klass(klass):
                        entry = RubyObjectEntry(
                            address=current + offset,
                            type_name=RUBY_TYPES[type_id],
                            flags=flags,
                            klass_ptr=klass,
                        )
                        count += 1
                        yield entry

                offset += RVALUE_SIZE

            current += page_size

    def _plausible_klass(self, klass: int) -> bool:
        """Check if a klass pointer looks valid for userspace."""
        if klass == 0:
            return True
        return 0x400000 < klass < 0x800000000000

    def _extract_value_preview(self, layer, entry: RubyObjectEntry) -> None:
        """Extract a human-readable preview of the object's value."""
        try:
            raw = layer.read(entry.address, RVALUE_SIZE)
        except exceptions.InvalidAddressException:
            return

        if entry.type_name == "STRING":
            entry.value_preview = self._extract_string_preview(layer, raw, entry.flags)
            if entry.flags & STR_NOEMBED:
                str_len = struct.unpack_from("<q", raw, 16)[0]
                entry.size_estimate = RVALUE_SIZE + max(0, str_len)

        elif entry.type_name == "ARRAY":
            entry.value_preview = self._extract_array_preview(raw, entry.flags)

        elif entry.type_name == "HASH":
            num_entries = struct.unpack_from("<q", raw, 16)[0]
            if 0 < num_entries < 1000000:
                entry.value_preview = f"Hash({num_entries} entries)"

        elif entry.type_name == "FLOAT":
            try:
                val = struct.unpack_from("<d", raw, 16)[0]
                entry.value_preview = f"{val}"
            except struct.error:
                pass

    def _extract_string_preview(
        self, layer, raw: bytes, flags: int
    ) -> str:
        """Extract string content from an RValue."""
        if flags & STR_NOEMBED:
            str_len = struct.unpack_from("<q", raw, 16)[0]
            str_ptr = struct.unpack_from("<Q", raw, 24)[0]
            if str_len <= 0 or str_len > 10000 or str_ptr == 0:
                return ""
            try:
                preview_len = min(str_len, 120)
                data = layer.read(str_ptr, preview_len)
                return data.decode("utf-8", errors="replace")
            except exceptions.InvalidAddressException:
                return ""
        else:
            embed_len = (flags & 0x1F0000) >> 16
            if 0 < embed_len <= 24:
                return raw[16 : 16 + embed_len].decode("utf-8", errors="replace")
        return ""

    def _extract_array_preview(self, raw: bytes, flags: int) -> str:
        """Extract array length preview."""
        arr_len = struct.unpack_from("<q", raw, 16)[0]
        if 0 < arr_len < 1000000:
            return f"Array(len={arr_len})"
        return ""

    def _extract_references(self, layer, entry: RubyObjectEntry) -> None:
        """Extract pointer references from an RValue's payload."""
        try:
            raw = layer.read(entry.address, RVALUE_SIZE)
        except exceptions.InvalidAddressException:
            return

        # Scan the payload area (bytes 16-39) for valid pointers
        for off in range(16, RVALUE_SIZE - POINTER_SIZE + 1, POINTER_SIZE):
            ptr = struct.unpack_from("<Q", raw, off)[0]
            if self._plausible_klass(ptr) and ptr != 0:
                entry.references.append(ptr)

    def _find_hidden_objects(
        self, layer, known_objects: List[RubyObjectEntry]
    ) -> List[RubyObjectEntry]:
        """Look for valid-looking RValues outside normal heap regions."""
        known_addrs = set(obj.address for obj in known_objects)
        hidden = []

        # Simple heuristic: scan random-looking offsets for orphaned objects
        # In production, this would check against the heap page list
        for obj in known_objects[:100]:
            for ref in obj.references:
                if ref not in known_addrs and ref != 0:
                    try:
                        data = layer.read(ref, RVALUE_SIZE)
                        flags = struct.unpack_from("<Q", data, 0)[0]
                        type_id = flags & T_MASK
                        if type_id in RUBY_TYPES and type_id != 0:
                            klass = struct.unpack_from("<Q", data, 8)[0]
                            if self._plausible_klass(klass):
                                entry = RubyObjectEntry(
                                    ref, RUBY_TYPES[type_id], flags, klass
                                )
                                entry.value_preview = "[HIDDEN]"
                                hidden.append(entry)
                                known_addrs.add(ref)
                    except exceptions.InvalidAddressException:
                        continue

        return hidden

    def _resolve_class_name(self, layer, klass_ptr: int) -> str:
        """Attempt to resolve a class pointer to a human-readable name."""
        try:
            klass_data = layer.read(klass_ptr, RVALUE_SIZE)
            flags = struct.unpack_from("<Q", klass_data, 0)[0]
            type_id = flags & T_MASK
            if type_id not in (0x02, 0x03):  # T_CLASS or T_MODULE
                return ""
            # Class name is typically stored as a string reference
            name_ptr = struct.unpack_from("<Q", klass_data, 24)[0]
            if name_ptr == 0:
                return ""
            name_data = layer.read(name_ptr, 128)
            null_pos = name_data.find(b"\x00")
            if null_pos > 0:
                return name_data[:null_pos].decode("utf-8", errors="replace")
        except (exceptions.InvalidAddressException, struct.error):
            pass
        return ""

    def _write_json_dump(
        self,
        path: str,
        objects: List[RubyObjectEntry],
        stats: dict,
    ) -> None:
        """Write ObjectSpace dump to JSON file."""
        output = {
            "metadata": {
                "plugin": "RubyObjectSpaceDump",
                "version": "1.0.0",
                "total_objects": stats["total"],
                "type_distribution": stats["by_type"],
                "hidden_candidates": stats["hidden_candidates"],
            },
            "objects": [obj.to_dict() for obj in objects],
        }
        with open(path, "w") as f:
            json.dump(output, f, indent=2)
        logger.info("Wrote ObjectSpace dump to %s (%d objects)", path, len(objects))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", str),
                ("Type", str),
                ("Class", str),
                ("Frozen", bool),
                ("Size", int),
                ("References", int),
                ("Preview", str),
            ],
            self._generator(),
        )
