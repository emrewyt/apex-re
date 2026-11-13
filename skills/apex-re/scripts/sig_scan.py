#!/usr/bin/env python3
"""
Apex-RE Pattern & Wildcard Signature Scanner (sig_scan.py)
Autonomous binary pattern matching, RIP-relative displacement resolution,
and stable signature synthesis for AI coding agents.

Zero external dependencies. Python 3.8+ compatible.
"""

import sys
import os
import re
import struct
import json
from typing import List, Dict, Optional, Tuple, Any

class PatternScanner:
    """High-performance pattern scanner with wildcard and RIP-relative displacement support."""

    @staticmethod
    def parse_ida_pattern(pattern_str: str) -> Tuple[bytes, bytes]:
        """
        Parses an IDA / Cheat Engine style pattern string into (pattern_bytes, mask_bytes).
        e.g. "48 8B 05 ? ? ? ? 48 85 C0" -> pattern and mask.
        """
        tokens = pattern_str.strip().split()
        pat_list = []
        mask_list = []

        for token in tokens:
            if token in ('?', '??'):
                pat_list.append(0x00)
                mask_list.append(0x00)
            else:
                pat_list.append(int(token, 16))
                mask_list.append(0xFF)

        return bytes(pat_list), bytes(mask_list)

    @classmethod
    def scan_pattern(cls, data: bytes, pattern: bytes, mask: bytes, max_matches: int = 100) -> List[int]:
        """
        Scans a binary buffer for pattern matching the given mask.
        Returns list of integer offsets where matches occur.
        """
        pat_len = len(pattern)
        data_len = len(data)
        matches = []

        if pat_len == 0 or pat_len > data_len:
            return matches

        # Quick check optimization: first non-wildcard byte
        first_idx = 0
        while first_idx < pat_len and mask[first_idx] == 0:
            first_idx += 1

        if first_idx >= pat_len:
            # All wildcards - not allowed
            return matches

        first_byte = pattern[first_idx]
        pos = 0

        while pos <= data_len - pat_len:
            # Fast scan for first concrete byte
            found = data.find(bytes([first_byte]), pos + first_idx)
            if found == -1:
                break
            
            cand_pos = found - first_idx
            if cand_pos + pat_len > data_len:
                break

            # Compare remaining bytes with mask
            match = True
            for i in range(pat_len):
                if mask[i] != 0 and data[cand_pos + i] != pattern[i]:
                    match = False
                    break

            if match:
                matches.append(cand_pos)
                if len(matches) >= max_matches:
                    break

            pos = cand_pos + 1

        return matches

    @staticmethod
    def resolve_rip_relative(data: bytes, match_offset: int, disp_offset_within_match: int,
                             instruction_length: int, image_base: int = 0x140000000) -> Dict[str, Any]:
        """
        Calculates the target absolute Virtual Address (VA) for an x86_64 RIP-relative instruction.
        Formula: Target VA = ImageBase + MatchOffset + InstructionLength + int32(Displacement)
        """
        abs_disp_pos = match_offset + disp_offset_within_match
        if abs_disp_pos + 4 > len(data):
            return {"error": "Displacement offset out of bounds"}

        displacement = struct.unpack("<i", data[abs_disp_pos:abs_disp_pos + 4])[0]
        next_rip_offset = match_offset + instruction_length
        target_rva = next_rip_offset + displacement
        target_va = image_base + target_rva

        return {
            "match_offset": match_offset,
            "match_rva": hex(match_offset),
            "displacement": displacement,
            "target_rva": hex(target_rva),
            "target_va": hex(target_va),
            "target_rva_int": target_rva,
            "target_va_int": target_va
        }

    @staticmethod
    def synthesize_unique_signature(data: bytes, target_offset: int, max_length: int = 64,
                                   wildcard_disp: bool = True) -> Optional[Dict[str, Any]]:
        """
        Autonomously synthesizes a stable, unique IDA-style signature for code at target_offset.
        """
        data_len = len(data)
        if target_offset < 0 or target_offset >= data_len:
            return None

        # Build progressive signature
        for current_len in range(8, min(max_length + 1, data_len - target_offset)):
            candidate_bytes = data[target_offset:target_offset + current_len]
            pat_tokens = []
            mask_tokens = []

            i = 0
            while i < current_len:
                # Detect x86_64 RIP-relative MOV (48 8B 05 ?? ?? ?? ??) or CALL (E8 ?? ?? ?? ??)
                if wildcard_disp and i + 7 <= current_len and candidate_bytes[i:i+3] == b"\x48\x8B\x05":
                    pat_tokens.extend(["48", "8B", "05", "?", "?", "?", "?"])
                    mask_tokens.extend([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])
                    i += 7
                elif wildcard_disp and i + 5 <= current_len and candidate_bytes[i] in (0xE8, 0xE9):
                    pat_tokens.extend([f"{candidate_bytes[i]:02X}", "?", "?", "?", "?"])
                    mask_tokens.extend([0xFF, 0x00, 0x00, 0x00, 0x00])
                    i += 5
                else:
                    pat_tokens.append(f"{candidate_bytes[i]:02X}")
                    mask_tokens.append(0xFF)
                    i += 1

            pat_str = " ".join(pat_tokens)
            p_bytes, m_bytes = PatternScanner.parse_ida_pattern(pat_str)
            matches = PatternScanner.scan_pattern(data, p_bytes, m_bytes, max_matches=2)

            if len(matches) == 1 and matches[0] == target_offset:
                return {
                    "pattern": pat_str,
                    "length": len(p_bytes),
                    "unique": True,
                    "offset": target_offset
                }

        # Non-wildcarded fallback if wildcarded was ambiguous
        for current_len in range(8, min(max_length + 1, data_len - target_offset)):
            candidate_bytes = data[target_offset:target_offset + current_len]
            pat_str = " ".join(f"{b:02X}" for b in candidate_bytes)
            p_bytes, m_bytes = PatternScanner.parse_ida_pattern(pat_str)
            matches = PatternScanner.scan_pattern(data, p_bytes, m_bytes, max_matches=2)
            if len(matches) == 1:
                return {
                    "pattern": pat_str,
                    "length": current_len,
                    "unique": True,
                    "offset": target_offset
                }

        return None


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python sig_scan.py scan <binary_file> '<IDA_pattern>' [--rip <disp_off> <insn_len>] [--base <0xHex>]")
        print("  python sig_scan.py synth <binary_file> <target_offset_hex_or_dec> [--max-len <64>]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    bin_path = sys.argv[2]

    if not os.path.exists(bin_path):
        print(f"Error: Target binary not found: {bin_path}", file=sys.stderr)
        sys.exit(1)

    with open(bin_path, "rb") as f:
        data = f.read()

    if cmd == "scan":
        pattern_str = sys.argv[3]
        base_addr = 0x140000000
        rip_disp_off = None
        rip_insn_len = None

        idx = 4
        while idx < len(sys.argv):
            if sys.argv[idx] == "--base" and idx + 1 < len(sys.argv):
                base_addr = int(sys.argv[idx + 1], 16 if "x" in sys.argv[idx + 1] else 10)
                idx += 2
            elif sys.argv[idx] == "--rip" and idx + 2 < len(sys.argv):
                rip_disp_off = int(sys.argv[idx + 1])
                rip_insn_len = int(sys.argv[idx + 2])
                idx += 3
            else:
                idx += 1

        pat_bytes, mask_bytes = PatternScanner.parse_ida_pattern(pattern_str)
        matches = PatternScanner.scan_pattern(data, pat_bytes, mask_bytes)

        print(f"[*] Scanned {len(data)} bytes with pattern: '{pattern_str}'")
        print(f"[*] Found {len(matches)} match(es):")

        for m in matches:
            info_str = f"  Offset: 0x{m:08X} (RVA: +0x{m:X}, VA: 0x{base_addr + m:016X})"
            if rip_disp_off is not None and rip_insn_len is not None:
                rip_info = PatternScanner.resolve_rip_relative(data, m, rip_disp_off, rip_insn_len, base_addr)
                if "error" not in rip_info:
                    info_str += f" -> RIP Target VA: {rip_info['target_va']} (disp: {rip_info['displacement']})"
            print(info_str)

    elif cmd == "synth":
        target_off_str = sys.argv[3]
        target_off = int(target_off_str, 16 if "x" in target_off_str.lower() else 10)
        max_len = 64
        if "--max-len" in sys.argv:
            idx = sys.argv.index("--max-len")
            if idx + 1 < len(sys.argv):
                max_len = int(sys.argv[idx + 1])

        result = PatternScanner.synthesize_unique_signature(data, target_off, max_length=max_len)
        if result:
            print(f"[+] Successfully synthesized unique signature for offset 0x{target_off:08X}:")
            print(f"  Pattern : {result['pattern']}")
            print(f"  Length  : {result['length']} bytes")
            print(f"\nC++ Macro:")
            print(f'#define SIG_TARGET "{result["pattern"]}"')
            print(f"\nC# Static:")
            print(f'public const string SigTarget = "{result["pattern"]}";')
        else:
            print(f"[-] Could not find a unique signature within {max_len} bytes.")

if __name__ == "__main__":
    main()
