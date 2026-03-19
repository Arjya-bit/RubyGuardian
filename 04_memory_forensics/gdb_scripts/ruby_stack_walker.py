"""
RubyGuardian -- GDB Python Script: Ruby Stack Walker

Provides GDB commands for walking both the native C stack and the Ruby
VM execution context stack. Reconstructs Ruby call frames, identifies
suspicious eval/send chains, and detects stack-based attacks.

Usage from GDB:
    source ruby_stack_walker.py
    ruby-stack
    ruby-stack-eval-chain
    ruby-stack-detect-anomalies
"""

import gdb
import struct
import re
from collections import defaultdict

# Ruby VM frame types (iseq, cfunc, etc.)
VM_FRAME_MAGIC_METHOD = 0x11110001
VM_FRAME_MAGIC_BLOCK = 0x21110001
VM_FRAME_MAGIC_CLASS = 0x31110001
VM_FRAME_MAGIC_TOP = 0x51110001
VM_FRAME_MAGIC_CFUNC = 0x61110001
VM_FRAME_MAGIC_EVAL = 0x71110001
VM_FRAME_MAGIC_RESCUE = 0x81110001

FRAME_TYPE_NAMES = {
    VM_FRAME_MAGIC_METHOD: "METHOD",
    VM_FRAME_MAGIC_BLOCK: "BLOCK",
    VM_FRAME_MAGIC_CLASS: "CLASS",
    VM_FRAME_MAGIC_TOP: "TOP",
    VM_FRAME_MAGIC_CFUNC: "CFUNC",
    VM_FRAME_MAGIC_EVAL: "EVAL",
    VM_FRAME_MAGIC_RESCUE: "RESCUE",
}

# Suspicious method names that may indicate malicious activity
SUSPICIOUS_METHODS = {
    "eval", "instance_eval", "class_eval", "module_eval",
    "send", "__send__", "public_send",
    "system", "exec", "spawn", "`",
    "method_missing", "const_missing",
    "define_method", "remove_method",
    "instance_variable_set", "instance_variable_get",
    "binding", "ObjectSpace",
}


def read_memory(address, size):
    """Read raw bytes from inferior memory."""
    inferior = gdb.selected_inferior()
    try:
        return bytes(inferior.read_memory(address, size))
    except gdb.MemoryError:
        return None


def read_pointer(address):
    """Read a 64-bit pointer."""
    data = read_memory(address, 8)
    if data is None:
        return 0
    return struct.unpack("<Q", data)[0]


def read_cstring(address, max_len=256):
    """Read a null-terminated C string."""
    data = read_memory(address, max_len)
    if data is None:
        return None
    null_pos = data.find(b"\x00")
    if null_pos >= 0:
        data = data[:null_pos]
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


def get_ruby_thread():
    """Locate the current Ruby thread execution context."""
    try:
        ec = gdb.parse_and_eval("ruby_current_ec")
        return ec
    except gdb.error:
        pass

    try:
        vm = gdb.parse_and_eval("ruby_current_vm_ptr")
        main_ractor = vm["ractor"]["main_ractor"]
        running_ec = main_ractor["threads"]["running_ec"]
        return running_ec
    except gdb.error:
        return None


class RubyFrame:
    """Represents a single Ruby execution frame."""

    def __init__(self, index, frame_type, method_name, file_path,
                 line_number, address, is_suspicious=False):
        self.index = index
        self.frame_type = frame_type
        self.method_name = method_name
        self.file_path = file_path
        self.line_number = line_number
        self.address = address
        self.is_suspicious = is_suspicious

    def display(self):
        marker = " [!]" if self.is_suspicious else ""
        location = ""
        if self.file_path:
            location = f" at {self.file_path}"
            if self.line_number > 0:
                location += f":{self.line_number}"
        return (
            f"  #{self.index:>3} [{self.frame_type:<7}] "
            f"{self.method_name or '<unknown>'}{location}"
            f" ({self.address:#018x}){marker}"
        )


class RubyStack(gdb.Command):
    """Walk the Ruby VM stack and display call frames.
    Usage: ruby-stack [max_depth]"""

    def __init__(self):
        super().__init__("ruby-stack", gdb.COMMAND_STACK)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        max_depth = int(args[0]) if args else 200

        print("[RubyGuardian] Walking Ruby VM stack...")

        ec = get_ruby_thread()
        if ec is None:
            print("  Error: Could not locate Ruby execution context.")
            print("  Ensure you are debugging a Ruby process with symbols.")
            return

        frames = self._walk_cfp_chain(ec, max_depth)

        if not frames:
            print("  No Ruby frames found. Trying native backtrace fallback...")
            self._native_fallback()
            return

        print(f"\n  Ruby Call Stack ({len(frames)} frames):")
        print(f"  {'=' * 72}")
        for frame in frames:
            print(frame.display())
        print(f"  {'=' * 72}")

        suspicious = [f for f in frames if f.is_suspicious]
        if suspicious:
            print(f"\n  WARNING: {len(suspicious)} suspicious frame(s) detected:")
            for f in suspicious:
                print(f"    - {f.method_name} at frame #{f.index}")

    def _walk_cfp_chain(self, ec, max_depth):
        """Walk the control frame pointer chain."""
        frames = []
        try:
            cfp = ec["cfp"]
            cfp_addr = int(cfp)

            # Calculate stack end from ec->vm_stack + ec->vm_stack_size
            stack_base = int(ec["vm_stack"])
            stack_size = int(ec["vm_stack_size"])
            stack_end = stack_base + stack_size
        except (gdb.error, KeyError):
            return frames

        depth = 0
        while cfp_addr != 0 and cfp_addr < stack_end and depth < max_depth:
            frame = self._parse_cfp(cfp_addr, depth)
            if frame:
                frames.append(frame)
            depth += 1

            # Move to the next frame (cfp is an array growing upward)
            cfp_size = self._get_cfp_size()
            cfp_addr += cfp_size

        return frames

    def _parse_cfp(self, cfp_addr, index):
        """Parse a single rb_control_frame_t."""
        try:
            cfp = gdb.Value(cfp_addr).cast(
                gdb.lookup_type("rb_control_frame_t").pointer()
            ).dereference()
        except gdb.error:
            return None

        try:
            frame_type_val = int(cfp["ep"][0]) if int(cfp["ep"]) != 0 else 0
            frame_type = FRAME_TYPE_NAMES.get(
                frame_type_val & 0xFFFF0001, "UNKNOWN"
            )
        except (gdb.error, KeyError):
            frame_type = "UNKNOWN"

        method_name = self._get_method_name(cfp)
        file_path, line_number = self._get_location(cfp)
        is_suspicious = method_name in SUSPICIOUS_METHODS if method_name else False

        return RubyFrame(
            index=index,
            frame_type=frame_type,
            method_name=method_name,
            file_path=file_path,
            line_number=line_number,
            address=cfp_addr,
            is_suspicious=is_suspicious,
        )

    def _get_method_name(self, cfp):
        """Extract the method name from a control frame."""
        try:
            iseq = cfp["iseq"]
            if int(iseq) != 0:
                body = iseq["body"]
                location = body["location"]
                label = location["label"]
                # label is a VALUE (Ruby string)
                return self._rstring_to_str(int(label))
        except (gdb.error, KeyError):
            pass

        # Try CFUNC name
        try:
            me = cfp["me"]
            if int(me) != 0:
                called_id = me["called_id"]
                return self._id_to_str(int(called_id))
        except (gdb.error, KeyError):
            pass

        return None

    def _get_location(self, cfp):
        """Extract file path and line number from a control frame."""
        try:
            iseq = cfp["iseq"]
            if int(iseq) == 0:
                return None, 0

            body = iseq["body"]
            location = body["location"]
            pathobj = location["pathobj"]
            path_str = self._rstring_to_str(int(pathobj))

            # Get line number from PC offset
            pc = int(cfp["pc"])
            iseq_encoded = int(body["iseq_encoded"])
            if pc > 0 and iseq_encoded > 0:
                offset = (pc - iseq_encoded) // 8
                # Simplified line number lookup
                first_lineno = int(location["first_lineno"])
                return path_str, first_lineno
            return path_str, 0
        except (gdb.error, KeyError):
            return None, 0

    def _rstring_to_str(self, value):
        """Convert a Ruby VALUE string to a Python string."""
        if value == 0 or value & 0x01:
            return None
        data = read_memory(value, 40)
        if data is None:
            return None
        flags = struct.unpack_from("<Q", data, 0)[0]
        if (flags & 0x1F) != 0x05:  # Not T_STRING
            return None
        if flags & (1 << 13):  # STR_NOEMBED
            str_len = struct.unpack_from("<q", data, 16)[0]
            str_ptr = struct.unpack_from("<Q", data, 24)[0]
            if str_len <= 0 or str_len > 1024:
                return None
            return read_cstring(str_ptr, min(str_len, 256))
        else:
            embed_len = (flags & 0x1F0000) >> 16
            if embed_len <= 0 or embed_len > 24:
                return None
            return data[16:16 + embed_len].decode("utf-8", errors="replace")

    def _id_to_str(self, id_val):
        """Convert a Ruby ID to a string name."""
        try:
            result = gdb.parse_and_eval(f"rb_id2name({id_val})")
            return result.string() if int(result) != 0 else None
        except gdb.error:
            return None

    def _get_cfp_size(self):
        """Get the size of rb_control_frame_t."""
        try:
            return gdb.lookup_type("rb_control_frame_t").sizeof
        except gdb.error:
            return 64  # Reasonable default

    def _native_fallback(self):
        """Fall back to native backtrace, filtering for Ruby frames."""
        try:
            bt = gdb.execute("bt 50", to_string=True)
            ruby_frames = [
                line for line in bt.split("\n")
                if any(kw in line for kw in ["rb_", "ruby", "vm_exec", "iseq"])
            ]
            if ruby_frames:
                print("  Native frames with Ruby symbols:")
                for line in ruby_frames:
                    print(f"    {line.strip()}")
        except gdb.error:
            print("  Native backtrace also failed.")


class RubyStackEvalChain(gdb.Command):
    """Detect eval/send chains in the Ruby stack.
    Usage: ruby-stack-eval-chain"""

    def __init__(self):
        super().__init__("ruby-stack-eval-chain", gdb.COMMAND_STACK)

    def invoke(self, arg, from_tty):
        print("[RubyGuardian] Analyzing eval/send chains in Ruby stack...")

        ec = get_ruby_thread()
        if ec is None:
            print("  Error: Could not locate Ruby execution context.")
            return

        walker = RubyStack()
        frames = walker._walk_cfp_chain(ec, 500)

        eval_chain = []
        max_chain = 0
        chains = []

        for frame in frames:
            if frame.method_name in SUSPICIOUS_METHODS:
                eval_chain.append(frame)
            else:
                if len(eval_chain) >= 2:
                    chains.append(list(eval_chain))
                    max_chain = max(max_chain, len(eval_chain))
                eval_chain.clear()

        if eval_chain and len(eval_chain) >= 2:
            chains.append(eval_chain)

        if chains:
            print(f"\n  Found {len(chains)} suspicious eval/send chain(s):")
            for i, chain in enumerate(chains):
                print(f"\n  Chain #{i + 1} ({len(chain)} frames):")
                for f in chain:
                    print(f"    {f.display()}")
        else:
            print("  No suspicious eval/send chains detected.")


class RubyStackDetectAnomalies(gdb.Command):
    """Detect stack-based anomalies in the Ruby process.
    Usage: ruby-stack-detect-anomalies"""

    def __init__(self):
        super().__init__("ruby-stack-detect-anomalies", gdb.COMMAND_STACK)

    def invoke(self, arg, from_tty):
        print("[RubyGuardian] Checking for stack anomalies...")

        anomalies = []

        # Check for stack overflow proximity
        try:
            pid = gdb.selected_inferior().pid
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    if "[stack]" in line:
                        parts = line.split()
                        addr_range = parts[0].split("-")
                        stack_bottom = int(addr_range[0], 16)
                        stack_top = int(addr_range[1], 16)
                        sp = int(gdb.parse_and_eval("$rsp"))

                        remaining = sp - stack_bottom
                        if remaining < 4096:
                            anomalies.append({
                                "type": "stack_overflow_imminent",
                                "severity": "critical",
                                "detail": f"Only {remaining} bytes remaining on stack",
                            })
                        elif remaining < 65536:
                            anomalies.append({
                                "type": "deep_stack",
                                "severity": "high",
                                "detail": f"Stack usage very high: {remaining} bytes remaining",
                            })
        except (OSError, gdb.error):
            pass

        # Check for ROP gadget indicators on the stack
        try:
            sp = int(gdb.parse_and_eval("$rsp"))
            stack_data = read_memory(sp, 4096)
            if stack_data:
                ret_count = 0
                for i in range(0, len(stack_data) - 8, 8):
                    ptr = struct.unpack_from("<Q", stack_data, i)[0]
                    if 0x400000 < ptr < 0x800000000000:
                        code = read_memory(ptr - 1, 2)
                        if code and code[0:1] == b"\xc3":
                            ret_count += 1
                if ret_count > 20:
                    anomalies.append({
                        "type": "possible_rop",
                        "severity": "critical",
                        "detail": f"{ret_count} potential ROP gadget pointers on stack",
                    })
        except gdb.error:
            pass

        if anomalies:
            print(f"\n  Found {len(anomalies)} anomaly/anomalies:")
            for a in anomalies:
                print(f"    [{a['severity'].upper()}] {a['type']}: {a['detail']}")
        else:
            print("  No stack anomalies detected.")


# Register commands
RubyStack()
RubyStackEvalChain()
RubyStackDetectAnomalies()
print("[RubyGuardian] Ruby stack walker loaded. Commands: "
      "ruby-stack, ruby-stack-eval-chain, ruby-stack-detect-anomalies")
