#!/usr/bin/env python3
"""
Apex-RE Virtual Machine Bytecode & Trace Analyzer (vm_analyzer.py)
Deconstructs obfuscated VM interpreter loops, filters dispatcher overhead,
classifies virtual handlers, and performs backward symbolic register slicing.

Zero external dependencies. Python 3.8+ compatible.
"""

import sys
import os
import re
import json
from typing import List, Dict, Set, Tuple, Optional, Any

class VMAnalyzer:
    """Analyzes VM execution traces, detects dispatchers, and slices semantic operations."""

    def __init__(self):
        self.trace: List[Dict[str, Any]] = []
        self.dispatcher_addresses: Set[int] = set()
        self.semantic_trace: List[Dict[str, Any]] = []

    def load_trace_json(self, json_path: str):
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                self.trace = data
            elif isinstance(data, dict) and "trace" in data:
                self.trace = data["trace"]

    def load_trace_text(self, text_path: str):
        """
        Parses text trace format:
        0x140001000: mov rax, [rsi]
        0x140001003: add rsi, 8
        """
        self.trace = []
        with open(text_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                m = re.match(r"(?:0x)?([0-9a-fA-F]+)\s*[:|-]\s*(.*)", line)
                if m:
                    addr = int(m.group(1), 16)
                    insn_text = m.group(2).strip()
                    parts = insn_text.split(None, 1)
                    mnemonic = parts[0].lower() if parts else ""
                    operands = parts[1] if len(parts) > 1 else ""
                    self.trace.append({
                        "address": addr,
                        "mnemonic": mnemonic,
                        "operands": operands,
                        "raw": insn_text
                    })

    def detect_dispatcher_loop(self, min_repetitions: int = 3) -> List[int]:
        """
        Detects addresses of VM dispatchers based on execution frequency.
        VM dispatchers typically execute far more frequently than individual handlers.
        """
        freq: Dict[int, int] = {}
        for entry in self.trace:
            addr = entry.get("address", 0)
            freq[addr] = freq.get(addr, 0) + 1

        if not freq:
            return []

        max_count = max(freq.values())
        threshold = max(min_repetitions, int(max_count * 0.75))
        self.dispatcher_addresses = {addr for addr, count in freq.items() if count >= threshold}
        return sorted(list(self.dispatcher_addresses))

    def filter_dispatcher_overhead(self) -> List[Dict[str, Any]]:
        """
        Filters out dispatcher addresses and VM pointer increment overhead.
        Retains semantic body operations.
        """
        if not self.dispatcher_addresses:
            self.detect_dispatcher_loop()

        filtered = []
        for entry in self.trace:
            addr = entry.get("address", 0)
            mnem = entry.get("mnemonic", "").lower()
            ops = entry.get("operands", "").lower()

            # Skip dispatcher head instructions
            if addr in self.dispatcher_addresses:
                continue

            # Skip VM instruction pointer tracking (e.g. add rsi, 4; lodsb; inc rsi)
            if mnem in ("lodsb", "lodsd", "lodsq"):
                continue
            if mnem in ("inc", "add") and any(reg in ops for reg in ("rsi", "r14", "r15", "eip", "rip")):
                # Likely virtual instruction pointer advance
                continue

            filtered.append(entry)

        self.semantic_trace = filtered
        return filtered

    @staticmethod
    def classify_instruction(insn: Dict[str, Any]) -> str:
        """Classifies instruction into semantic VM category."""
        mnem = insn.get("mnemonic", "").lower()
        if mnem in ("add", "sub", "imul", "mul", "idiv", "div", "neg", "inc", "dec"):
            return "ARITHMETIC"
        elif mnem in ("xor", "and", "or", "not", "shl", "shr", "sar", "rol", "ror"):
            return "LOGIC"
        elif mnem in ("mov", "movzx", "movsx", "lea"):
            return "DATA_TRANSFER"
        elif mnem in ("push", "pop"):
            return "STACK"
        elif mnem in ("cmp", "test"):
            return "COMPARISON"
        elif mnem.startswith("j"):
            return "BRANCH"
        elif mnem in ("call", "ret"):
            return "CALL_RETURN"
        return "UNKNOWN"

    def backward_slice(self, target_register: str, max_depth: int = 50) -> List[Dict[str, Any]]:
        """
        Traces backward dependencies for target_register across the semantic trace.
        Extracts only instructions directly contributing to the final value.
        """
        target_reg = target_register.lower()
        active_deps: Set[str] = {target_reg}
        slice_result: List[Dict[str, Any]] = []

        # Traverse backwards
        for insn in reversed(self.semantic_trace if self.semantic_trace else self.trace):
            mnem = insn.get("mnemonic", "").lower()
            ops = [op.strip() for op in insn.get("operands", "").lower().split(",") if op.strip()]

            if not ops:
                continue

            dst = ops[0]
            # Check if destination matches any active dependency
            dst_matches = any(dep in dst for dep in active_deps)

            if dst_matches:
                slice_result.append(insn)
                # If instruction overwrites destination, we can remove it unless it's an in-place op (add/xor)
                if mnem not in ("add", "sub", "xor", "and", "or", "shl", "shr"):
                    # Remove dst from deps if it was a plain write
                    active_deps = {dep for dep in active_deps if dep not in dst}

                # Add source operands to dependencies
                for src in ops[1:]:
                    # Extract register names
                    regs = re.findall(r"\b[er]?[abcd]x|\b[er]?[sb]p|\b[er]?[sd]i|\br[89]|\br1[0-5]\b", src)
                    for r in regs:
                        active_deps.add(r)

                if len(slice_result) >= max_depth:
                    break

        slice_result.reverse()
        return slice_result

    def synthesize_expression(self, target_register: str = "rax") -> str:
        """
        Synthesizes high-level algebraic expression from backward sliced instructions.
        """
        sliced = self.backward_slice(target_register)
        if not sliced:
            return f"// No dependency chain found for {target_register}"

        lines = [f"// Semantic reconstruction for {target_register} ({len(sliced)} instructions):"]
        for insn in sliced:
            category = self.classify_instruction(insn)
            lines.append(f"    {insn.get('raw', '')};  // [{category}]")

        return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python vm_analyzer.py <trace.json_or_txt> [--slice <reg>] [--json]")
        sys.exit(1)

    trace_file = sys.argv[1]
    if not os.path.exists(trace_file):
        print(f"Error: Trace file not found: {trace_file}", file=sys.stderr)
        sys.exit(1)

    analyzer = VMAnalyzer()
    if trace_file.endswith(".json"):
        analyzer.load_trace_json(trace_file)
    else:
        analyzer.load_trace_text(trace_file)

    dispatchers = analyzer.detect_dispatcher_loop()
    filtered = analyzer.filter_dispatcher_overhead()

    print(f"[*] Loaded trace with {len(analyzer.trace)} instructions.")
    print(f"[*] Identified {len(dispatchers)} dispatcher basic block(s): " +
          ", ".join(f"0x{a:X}" for a in dispatchers))
    print(f"[*] Retained {len(filtered)} semantic VM handler instructions.")

    target_reg = "rax"
    if "--slice" in sys.argv:
        idx = sys.argv.index("--slice")
        if idx + 1 < len(sys.argv):
            target_reg = sys.argv[idx + 1]

    expr = analyzer.synthesize_expression(target_reg)
    print("\n" + expr)

if __name__ == "__main__":
    main()
