#!/usr/bin/env python3
"""
Apex-RE Control Flow Unflattening Analyzer & Trace Reconstructor.
Deobfuscates OLLVM / state-dispatcher flattened control flow graphs (CFG)
into linear execution sequences and structured C pseudocode.
Zero dependencies (Python 3 standard library).
"""

import sys
import os
import json
import re
import argparse
from typing import Dict, Any, List, Optional, Set, Tuple

class ControlFlowUnflattener:
    def __init__(self, trace_data: List[Dict[str, Any]]):
        self.raw_trace = trace_data
        self.state_handlers: Dict[int, Dict[str, Any]] = {}
        self.transitions: List[Tuple[int, int, Optional[str]]] = []
        self.entry_state: Optional[int] = None
        self.terminal_states: Set[int] = set()

    @classmethod
    def from_json(cls, json_str: str) -> "ControlFlowUnflattener":
        data = json.loads(json_str)
        if isinstance(data, dict) and "trace" in data:
            data = data["trace"]
        return cls(data)

    @classmethod
    def from_text_log(cls, text: str) -> "ControlFlowUnflattener":
        """Parses log lines with patterns like: State: 0x1 -> Block: BB_1 -> Code: 'x = 1;' -> Next: 0x2"""
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            state_m = re.search(r"state[:\s]+(0x[0-9a-fA-F]+|\d+)", line, re.IGNORECASE)
            block_m = re.search(r"block[:\s]+(\w+)", line, re.IGNORECASE)
            code_m = re.search(r"code[:\s]+['\"](.*?)['\"]", line, re.IGNORECASE)
            next_m = re.search(r"next[:\s]+(0x[0-9a-fA-F]+|\d+|exit|return)", line, re.IGNORECASE)

            if state_m:
                s_val = int(state_m.group(1), 0)
                b_name = block_m.group(1) if block_m else f"bb_{s_val}"
                code = code_m.group(1) if code_m else f"/* execute {b_name} */"
                n_val = None
                if next_m:
                    n_raw = next_m.group(1).lower()
                    if n_raw not in ("exit", "return"):
                        n_val = int(n_raw, 0)

                entries.append({
                    "state": s_val,
                    "block": b_name,
                    "code": code,
                    "next_state": n_val
                })
        return cls(entries)

    def analyze(self):
        if not self.raw_trace:
            return

        self.entry_state = self.raw_trace[0]["state"]

        for item in self.raw_trace:
            st = item["state"]
            block = item.get("block", f"bb_state_{st}")
            code = item.get("code", "")
            nxt = item.get("next_state")
            cond = item.get("condition")

            if st not in self.state_handlers:
                self.state_handlers[st] = {
                    "block": block,
                    "code": code,
                    "successors": []
                }
            
            if nxt is not None:
                self.transitions.append((st, nxt, cond))
                if nxt not in [s[0] for s in self.state_handlers[st]["successors"]]:
                    self.state_handlers[st]["successors"].append((nxt, cond))
            else:
                self.terminal_states.add(st)

    def reconstruct_c_code(self) -> str:
        """Emits clean, de-flattened structured C code."""
        lines = []
        lines.append("// Apex-RE De-obfuscated Control Flow")
        lines.append("// Dispatcher loop and artificial state variables removed")
        lines.append("")
        lines.append("void reconstructed_function() {")

        visited = set()
        curr: Optional[int] = self.entry_state

        while curr is not None and curr not in visited:
            visited.add(curr)
            handler = self.state_handlers.get(curr)
            if not handler:
                lines.append(f"    // Warning: Unresolved state 0x{curr:X}")
                break

            lines.append(f"    // State 0x{curr:X} [{handler['block']}]")
            if handler["code"]:
                for c_line in handler["code"].split(";"):
                    c_line = c_line.strip()
                    if c_line:
                        lines.append(f"    {c_line};")

            successors = handler["successors"]
            if not successors:
                lines.append("    return;")
                curr = None
            elif len(successors) == 1:
                next_st, _ = successors[0]
                if next_st in visited:
                    lines.append(f"    // Loop back-edge detected -> State 0x{next_st:X}")
                    lines.append(f"    goto state_0x{next_st:X};")
                    curr = None
                else:
                    curr = next_st
            else:
                # Conditional branching
                s1, c1 = successors[0]
                s2, c2 = successors[1]
                cond_str = c1 or "condition"
                lines.append(f"    if ({cond_str}) {{")
                lines.append(f"        // Branch to state 0x{s1:X}")
                lines.append(f"    }} else {{")
                lines.append(f"        // Branch to state 0x{s2:X}")
                lines.append(f"    }}")
                # Follow main branch
                curr = s1 if s1 not in visited else (s2 if s2 not in visited else None)

        lines.append("}")
        return "\n".join(lines)

    def generate_mermaid(self) -> str:
        """Generates Mermaid flowchart showing the recovered CFG without dispatchers."""
        lines = ["flowchart TD"]
        for st, h in self.state_handlers.items():
            b_label = f"State 0x{st:X}: {h['block']}"
            lines.append(f"    node_{st}[\"{b_label}\"]")

        for src, dst, cond in self.transitions:
            if cond:
                lines.append(f"    node_{src} -- \"{cond}\" --> node_{dst}")
            else:
                lines.append(f"    node_{src} --> node_{dst}")
        return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Apex-RE Control Flow Flattening (CFF) Deobfuscator")
    parser.add_argument("input_trace", help="JSON or text log file containing state transitions")
    parser.add_argument("--format", choices=["c", "mermaid", "json"], default="c", help="Output format (default: c)")
    args = parser.parse_args()

    if not os.path.exists(args.input_trace):
        sys.stderr.write(f"Error: Trace file {args.input_trace} not found.\n")
        sys.exit(1)

    with open(args.input_trace, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        unflattener = ControlFlowUnflattener.from_json(content)
    except Exception:
        unflattener = ControlFlowUnflattener.from_text_log(content)

    unflattener.analyze()

    if args.format == "c":
        print(unflattener.reconstruct_c_code())
    elif args.format == "mermaid":
        print(unflattener.generate_mermaid())
    elif args.format == "json":
        print(json.dumps({
            "entry_state": unflattener.entry_state,
            "handlers": unflattener.state_handlers,
            "transitions": unflattener.transitions
        }, indent=2))

if __name__ == "__main__":
    main()
