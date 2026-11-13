#!/usr/bin/env python3
"""
Apex-RE Kaitai Struct Synthesizer.
Analyzes proprietary binary blobs / network packets and synthesizes valid Kaitai Struct (.ksy) YAML specifications.
Zero dependencies (Python 3 standard library).
"""

import sys
import os
import struct
import math
import argparse
from typing import Dict, Any, List, Optional, Tuple

class KaitaiSynthesizer:
    def __init__(self, data: bytes, struct_id: str = "binary_payload", endian: str = "auto"):
        self.data = data
        self.struct_id = struct_id
        self.endian = self._determine_endianness(endian)
        self.fields: List[Dict[str, Any]] = []

    def _determine_endianness(self, user_endian: str) -> str:
        if user_endian in ("le", "be"):
            return user_endian
        if len(self.data) < 8:
            return "le"

        # Heuristic: inspect 32-bit values in first 16 bytes
        # In LE, small values (e.g. lengths, counts < 65536) have zeros in high bytes: [val, 0, 0, 0]
        # In BE, they have zeros in low bytes: [0, 0, 0, val]
        le_zeros = 0
        be_zeros = 0
        for off in range(0, min(len(self.data) - 4, 32), 4):
            b = self.data[off:off+4]
            if b[2] == 0 and b[3] == 0 and (b[0] != 0 or b[1] != 0):
                le_zeros += 1
            if b[0] == 0 and b[1] == 0 and (b[2] != 0 or b[3] != 0):
                be_zeros += 1
        return "le" if le_zeros >= be_zeros else "be"

    def synthesize(self) -> str:
        self.fields.clear()
        offset = 0
        total_len = len(self.data)

        # 1. Magic check (first 2-4 bytes if printable ascii)
        if total_len >= 4:
            magic_candidate = self.data[:4]
            if all(32 <= b <= 126 for b in magic_candidate):
                self.fields.append({
                    "id": "magic",
                    "type": "str",
                    "size": 4,
                    "encoding": "ASCII",
                    "doc": f"Header signature ('{magic_candidate.decode('ascii')}')",
                    "contents": f"\"{magic_candidate.decode('ascii')}\""
                })
                offset += 4
            elif magic_candidate.startswith(b"\x00") or any(magic_candidate):
                # hex bytes
                hex_list = ", ".join(f"0x{b:02x}" for b in magic_candidate)
                self.fields.append({
                    "id": "magic",
                    "contents": f"[{hex_list}]",
                    "doc": "Magic binary header bytes"
                })
                offset += 4

        field_counter = 0

        prefix = "<" if self.endian == "le" else ">"

        # Scan remaining fields
        while offset < total_len:
            rem = total_len - offset
            field_name = f"field_{field_counter:02d}"

            # Check for null-terminated string candidate
            if rem >= 4 and 32 <= self.data[offset] <= 126:
                null_pos = self.data.find(b"\x00", offset)
                if null_pos != -1 and 3 <= (null_pos - offset) <= 64:
                    s_bytes = self.data[offset:null_pos]
                    if all(32 <= b <= 126 or b in (9, 10, 13) for b in s_bytes):
                        str_val = s_bytes.decode("latin1")
                        self.fields.append({
                            "id": f"str_{field_counter:02d}",
                            "type": "strz",
                            "encoding": "UTF-8",
                            "doc": f"Null-terminated string (sample: '{str_val[:20]}')"
                        })
                        offset = null_pos + 1
                        field_counter += 1
                        continue

            # Check for float32 candidate
            if rem >= 4:
                val_f32 = struct.unpack_from(f"{prefix}f", self.data, offset)[0]
                if not math.isnan(val_f32) and not math.isinf(val_f32) and 0.0001 <= abs(val_f32) <= 1000000.0 and abs(val_f32 - round(val_f32, 2)) < 0.05:
                    self.fields.append({
                        "id": f"float_{field_counter:02d}",
                        "type": "f4",
                        "doc": f"Offset 0x{offset:04X} (float sample: {val_f32:.4f})"
                    })
                    offset += 4
                    field_counter += 1
                    continue

            # Standard primitives
            is_u64 = False
            if rem >= 8 and (offset % 8 == 0 or rem == 8):
                val_u64 = struct.unpack_from(f"{prefix}Q", self.data, offset)[0]
                # True 64-bit integer indicated by non-zero upper 32-bits (timestamps, 64-bit GUIDs, offsets)
                if val_u64 > 0xFFFFFFFF:
                    is_u64 = True
                    self.fields.append({
                        "id": f"val64_{field_counter:02d}",
                        "type": "u8",
                        "doc": f"Offset 0x{offset:04X} (uint64: {val_u64} / 0x{val_u64:X})"
                    })
                    offset += 8

            if not is_u64:
                if rem >= 4:
                    val_u32 = struct.unpack_from(f"{prefix}I", self.data, offset)[0]
                    self.fields.append({
                        "id": f"uint_{field_counter:02d}",
                        "type": "u4",
                        "doc": f"Offset 0x{offset:04X} (uint32: {val_u32} / 0x{val_u32:X})"
                    })
                    offset += 4
                elif rem >= 2:
                    val_u16 = struct.unpack_from(f"{prefix}H", self.data, offset)[0]
                    self.fields.append({
                        "id": f"word_{field_counter:02d}",
                        "type": "u2",
                        "doc": f"Offset 0x{offset:04X} (uint16: {val_u16})"
                    })
                    offset += 2
                else:
                    self.fields.append({
                        "id": f"byte_{field_counter:02d}",
                        "type": "u1",
                        "doc": f"Offset 0x{offset:04X} (raw byte: 0x{self.data[offset]:02X})"
                    })
                    offset += 1
            field_counter += 1

        # Emit Kaitai Struct YAML
        lines = []
        lines.append(f"meta:")
        lines.append(f"  id: {self.struct_id}")
        lines.append(f"  file-extension: bin")
        lines.append(f"  endian: {self.endian}")
        lines.append(f"")
        lines.append(f"doc: |")
        lines.append(f"  Synthesized specification for {self.struct_id} ({total_len} bytes)")
        lines.append(f"  Generated autonomously by Apex-RE Kaitai Synthesizer.")
        lines.append(f"")
        lines.append(f"seq:")

        for f in self.fields:
            lines.append(f"  - id: {f['id']}")
            if "contents" in f:
                lines.append(f"    contents: {f['contents']}")
            elif "type" in f:
                lines.append(f"    type: {f['type']}")
            if "size" in f:
                lines.append(f"    size: {f['size']}")
            if "encoding" in f:
                lines.append(f"    encoding: {f['encoding']}")
            if "doc" in f:
                lines.append(f"    doc: \"{f['doc']}\"")

        return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Apex-RE Kaitai Struct YAML Synthesizer")
    parser.add_argument("input_file", help="Binary file or dump to synthesize specification for")
    parser.add_argument("--id", default="custom_binary", help="Identifier for Kaitai struct (default: custom_binary)")
    parser.add_argument("--endian", default="auto", choices=["auto", "le", "be"], help="Endianness mode (default: auto)")
    parser.add_argument("--output", "-o", default=None, help="Save generated .ksy to file")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        sys.stderr.write(f"Error: Input file {args.input_file} not found.\n")
        sys.exit(1)

    with open(args.input_file, "rb") as f:
        data = f.read()

    synth = KaitaiSynthesizer(data, struct_id=args.id, endian=args.endian)
    ksy_content = synth.synthesize()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(ksy_content)
        print(f"Kaitai Struct specification saved successfully to: {args.output}")
    else:
        print(ksy_content)

if __name__ == "__main__":
    main()
