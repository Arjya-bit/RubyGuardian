"""
RubyGuardian -- GDB Python Script: Ruby Heap Inspector

Provides GDB commands for inspecting Ruby heap structures in a live
or core-dumped Ruby process. Walks heap pages, examines RValues, and
detects anomalous allocation patterns.

Usage from GDB:
    source ruby_heap_inspector.py
    ruby-heap-summary
    ruby-heap-page <address>
    ruby-heap-anomalies
"""

import gdb
import struct
import json
from collections import defaultdict

# Ruby VM constants for 3.x
RVALUE_SIZE = 40
HEAP_PAGE_OBJ_LIMIT = 409
T_MASK = 0x1F

RUBY_TYPES = {
    0x00: "T_NONE",   0x01: "T_OBJECT", 0x02: "T_CLASS",
    0x03: "T_MODULE", 0x04: "T_FLOAT",  0x05: "T_STRING",
    0x06: "T_REGEXP", 0x07: "T_ARRAY",  0x08: "T_HASH",
    0x09: "T_STRUCT", 0x0A: "T_BIGNUM", 0x0B: "T_FILE",
    0x0C: "T_DATA",   0x0D: "T_MATCH",  0x0E: "T_COMPLEX",
    0x0F: "T_RATIONAL", 0x1A: "T_IMEMO", 0x1B: "T_NODE",
    0x1C: "T_ICLASS", 0x1D: "T_ZOMBIE", 0x1E: "T_MOVED",
}

STR_NOEMBED = 1 << 13


def read_memory(address, size):
    """Read raw bytes from the inferior's memory."""
    inferior = gdb.selected_inferior()
    try:
        return bytes(inferior.read_memory(address, size))
    except gdb.MemoryError:
        return None


def read_pointer(address):
    """Read a 64-bit pointer from memory."""
    data = read_memory(address, 8)
    if data is None:
        return None
    return struct.unpack("<Q", data)[0]


def read_rvalue(address):
    """Read and parse an RValue structure at the given address."""
    data = read_memory(address, RVALUE_SIZE)
    if data is None:
        return None

    flags = struct.unpack_from("<Q", data, 0)[0]
    klass = struct.unpack_from("<Q", data, 8)[0]
    type_id = flags & T_MASK
    type_name = RUBY_TYPES.get(type_id, f"T_UNKNOWN({type_id:#x})")

    return {
        "address": address,
        "flags": flags,
        "klass": klass,
        "type_id": type_id,
        "type_name": type_name,
        "raw": data,
    }


def extract_string_value(rv):
    """Extract the string content from a T_STRING RValue."""
    flags = rv["flags"]
    raw = rv["raw"]

    if flags & STR_NOEMBED:
        str_len = struct.unpack_from("<q", raw, 16)[0]
        str_ptr = struct.unpack_from("<Q", raw, 24)[0]
        if str_len <= 0 or str_len > 65536 or str_ptr == 0:
            return None
        data = read_memory(str_ptr, min(str_len, 256))
        if data is None:
            return None
        return data.decode("utf-8", errors="replace")
    else:
        embed_len = (flags & 0x1F0000) >> 16
        if embed_len <= 0 or embed_len > 24:
            return None
        return raw[16:16 + embed_len].decode("utf-8", errors="replace")


class RubyHeapSummary(gdb.Command):
    """Display a summary of the Ruby heap, including type distribution
    and basic statistics. Usage: ruby-heap-summary [max_pages]"""

    def __init__(self):
        super().__init__("ruby-heap-summary", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        max_pages = int(args[0]) if args else 500

        print("[RubyGuardian] Scanning Ruby heap pages...")

        # Locate the Ruby VM's heap via rb_objspace symbol
        heap_pages_found = 0
        type_dist = defaultdict(int)
        total_objects = 0
        total_free = 0
        anomaly_pages = []

        # Try to find heap pages through objspace
        try:
            objspace = gdb.parse_and_eval("ruby_current_vm->objspace")
            heap_pages_addr = int(objspace["heap_pages"]["sorted"])
            heap_pages_len = int(objspace["heap_pages"]["sorted_length"])
            print(f"  Found {heap_pages_len} heap pages via objspace")
        except (gdb.error, KeyError):
            print("  Could not locate objspace directly, scanning memory...")
            heap_pages_addr = None
            heap_pages_len = 0

        if heap_pages_addr and heap_pages_len > 0:
            for i in range(min(heap_pages_len, max_pages)):
                page_ptr = read_pointer(heap_pages_addr + i * 8)
                if page_ptr is None or page_ptr == 0:
                    continue

                page_info = self._analyze_page(page_ptr)
                if page_info is None:
                    continue

                heap_pages_found += 1
                total_objects += page_info["used"]
                total_free += page_info["free"]
                for t, c in page_info["types"].items():
                    type_dist[t] += c

                if page_info.get("anomaly"):
                    anomaly_pages.append(page_info)
        else:
            # Fallback: scan heap memory region
            self._scan_heap_fallback(
                type_dist, max_pages,
                lambda info: (
                    total_objects,
                    total_free,
                    heap_pages_found,
                )
            )

        # Print results
        print(f"\n{'=' * 60}")
        print(f"  Ruby Heap Summary")
        print(f"{'=' * 60}")
        print(f"  Pages scanned:    {heap_pages_found}")
        print(f"  Total objects:    {total_objects}")
        print(f"  Free slots:       {total_free}")
        occupancy = (total_objects / max(total_objects + total_free, 1)) * 100
        print(f"  Occupancy:        {occupancy:.1f}%")
        print(f"\n  Type Distribution:")
        for type_name, count in sorted(type_dist.items(), key=lambda x: -x[1]):
            pct = (count / max(total_objects, 1)) * 100
            print(f"    {type_name:<15} {count:>8}  ({pct:.1f}%)")

        if anomaly_pages:
            print(f"\n  Anomalous Pages: {len(anomaly_pages)}")
            for ap in anomaly_pages[:10]:
                print(f"    {ap['address']:#018x}: {ap['anomaly']}")

        print(f"{'=' * 60}")

    def _analyze_page(self, page_addr):
        """Analyze a single heap page."""
        # Read the page body (the start field in rb_heap_page_body)
        try:
            body_addr = read_pointer(page_addr + 8)  # page->body
            if body_addr is None or body_addr == 0:
                return None
        except Exception:
            return None

        types = defaultdict(int)
        used = 0
        free = 0

        for slot in range(HEAP_PAGE_OBJ_LIMIT):
            addr = body_addr + slot * RVALUE_SIZE
            rv = read_rvalue(addr)
            if rv is None:
                break

            if rv["type_name"] == "T_NONE":
                free += 1
            else:
                used += 1
                types[rv["type_name"]] += 1

        anomaly = None
        total = used + free
        if total > 0:
            str_count = types.get("T_STRING", 0)
            if str_count > total * 0.95:
                anomaly = "string_dominated"
            elif used > total * 0.99 and used > 100:
                anomaly = "fully_packed"

        return {
            "address": page_addr,
            "body": body_addr,
            "used": used,
            "free": free,
            "types": dict(types),
            "anomaly": anomaly,
        }

    def _scan_heap_fallback(self, type_dist, max_pages, update_fn):
        """Fallback scan using /proc/self/maps to find heap regions."""
        print("  Fallback heap scan not fully implemented in this context")


class RubyHeapPage(gdb.Command):
    """Inspect a specific Ruby heap page. Usage: ruby-heap-page <address>"""

    def __init__(self):
        super().__init__("ruby-heap-page", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if not args:
            print("Usage: ruby-heap-page <address>")
            return

        addr = int(args[0], 0)
        print(f"[RubyGuardian] Inspecting heap page at {addr:#018x}")

        types = defaultdict(int)
        strings = []

        for slot in range(HEAP_PAGE_OBJ_LIMIT):
            slot_addr = addr + slot * RVALUE_SIZE
            rv = read_rvalue(slot_addr)
            if rv is None:
                break

            types[rv["type_name"]] += 1

            if rv["type_name"] == "T_STRING":
                val = extract_string_value(rv)
                if val and len(val) >= 4:
                    strings.append((slot_addr, val[:80]))

        print(f"\n  Slot distribution:")
        for type_name, count in sorted(types.items(), key=lambda x: -x[1]):
            print(f"    {type_name:<15} {count:>5}")

        if strings:
            print(f"\n  String values (first 20):")
            for saddr, sval in strings[:20]:
                safe = sval.replace("\n", "\\n").replace("\r", "\\r")
                print(f"    {saddr:#018x}: {safe}")


class RubyHeapAnomalies(gdb.Command):
    """Scan the Ruby heap for anomalies. Usage: ruby-heap-anomalies"""

    def __init__(self):
        super().__init__("ruby-heap-anomalies", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        print("[RubyGuardian] Scanning for heap anomalies...")

        anomalies = []

        # Check for executable heap regions via /proc/PID/maps
        try:
            pid = gdb.selected_inferior().pid
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    parts = line.split()
                    perms = parts[1] if len(parts) > 1 else ""
                    pathname = parts[-1] if len(parts) > 5 else ""
                    if "w" in perms and "x" in perms:
                        if "[vdso]" not in pathname and ".so" not in pathname:
                            addr_range = parts[0]
                            anomalies.append({
                                "type": "wx_memory",
                                "severity": "critical",
                                "detail": f"W+X region: {addr_range} ({pathname})",
                            })
        except (OSError, IndexError):
            print("  Warning: Could not read /proc/PID/maps")

        if anomalies:
            print(f"\n  Found {len(anomalies)} anomalies:")
            for a in anomalies:
                print(f"    [{a['severity'].upper()}] {a['type']}: {a['detail']}")
        else:
            print("  No heap anomalies detected.")


# Register commands when sourced
RubyHeapSummary()
RubyHeapPage()
RubyHeapAnomalies()
print("[RubyGuardian] Ruby heap inspector loaded. Commands: "
      "ruby-heap-summary, ruby-heap-page, ruby-heap-anomalies")
