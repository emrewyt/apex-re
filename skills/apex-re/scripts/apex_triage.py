#!/usr/bin/env python3
"""
Apex-RE Triage Engine: Deep binary architecture, runtime & obfuscation detector.
Zero-dependency, production-grade binary triager.
Supports PE32/PE32+, ELF32/ELF64, Mach-O, WASM, Godot PCK, Unity, Unreal, .NET, Electron, Tauri, Python.
"""

import sys
import os
import struct
import math
import json
import argparse
from typing import Dict, Any, List, Optional, Tuple

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte buffer (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = [0] * 256
    for b in data:
        frequencies[b] += 1
    for count in frequencies:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

class BinaryTriager:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        self.results: Dict[str, Any] = {
            "file": os.path.basename(file_path),
            "size_bytes": self.file_size,
            "format": "Unknown",
            "architecture": "Unknown",
            "endianness": "little",
            "entry_point": None,
            "entropy_total": 0.0,
            "runtimes": [],
            "game_engine": None,
            "packers_and_protections": [],
            "rich_header": [],
            "anti_analysis": [],
            "sections": [],
            "anomalies": []
        }

    def analyze(self) -> Dict[str, Any]:
        if not os.path.isfile(self.file_path) or self.file_size == 0:
            self.results["format"] = "Empty or Missing File"
            return self.results

        with open(self.file_path, "rb") as f:
            header_sample = f.read(min(self.file_size, 4096))
            f.seek(0)
            full_sample = f.read(min(self.file_size, 10 * 1024 * 1024)) # Sample up to 10MB for scan

        self.results["entropy_total"] = calculate_entropy(full_sample)

        # 1. Format Detection
        if header_sample.startswith(b"MZ"):
            self._parse_pe(header_sample)
        elif header_sample.startswith(b"\x7fELF"):
            self._parse_elf(header_sample)
        elif header_sample.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
            self._parse_macho(header_sample)
        elif header_sample.startswith(b"\x00asm"):
            self.results["format"] = "WebAssembly (WASM)"
            if len(header_sample) >= 8:
                version = struct.unpack("<I", header_sample[4:8])[0]
                self.results["architecture"] = f"WASM v{version}"
        elif header_sample.startswith(b"GDPC"):
            self.results["format"] = "Godot PCK Package"
            self.results["game_engine"] = "Godot"
        elif header_sample.startswith(b"UnityFS"):
            self.results["format"] = "Unity AssetBundle (UnityFS)"
            self.results["game_engine"] = "Unity"
        elif header_sample.startswith(b"PK\x03\x04"):
            self.results["format"] = "ZIP / Archive Container"

        # 2. Deep String / Symbol Signatures Scan
        self._scan_runtimes_and_engines(full_sample)

        # 3. Protection & Entropy Heuristics
        self._evaluate_protections()

        return self.results

    def _parse_pe(self, header: bytes):
        self.results["format"] = "PE (Portable Executable)"
        if len(header) < 0x40:
            return
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        self._parse_rich_header(header, pe_offset)
        if pe_offset + 24 > len(header):
            # Read further if pe_offset is outside 4KB
            with open(self.file_path, "rb") as f:
                f.seek(pe_offset)
                pe_sig_block = f.read(256)
        else:
            pe_sig_block = header[pe_offset:pe_offset+256]

        if not pe_sig_block.startswith(b"PE\x00\x00"):
            self.results["format"] = "MS-DOS Executable"
            return

        machine_id = struct.unpack_from("<H", pe_sig_block, 4)[0]
        num_sections = struct.unpack_from("<H", pe_sig_block, 6)[0]
        size_optional_header = struct.unpack_from("<H", pe_sig_block, 20)[0]

        arch_map = {
            0x14C: "x86 (32-bit)",
            0x8664: "x64 (AMD64 / 64-bit)",
            0xAA64: "ARM64",
            0x1C0: "ARM (Thumb)"
        }
        self.results["architecture"] = arch_map.get(machine_id, f"Unknown PE Machine (0x{machine_id:04X})")

        if size_optional_header > 0 and len(pe_sig_block) >= 24 + 2:
            magic_opt = struct.unpack_from("<H", pe_sig_block, 24)[0]
            if magic_opt == 0x10B:
                self.results["format"] = "PE32 (32-bit)"
                entry_point = struct.unpack_from("<I", pe_sig_block, 40)[0]
                self.results["entry_point"] = f"0x{entry_point:X}"
            elif magic_opt == 0x20B:
                self.results["format"] = "PE32+ (64-bit)"
                entry_point = struct.unpack_from("<I", pe_sig_block, 40)[0]
                self.results["entry_point"] = f"0x{entry_point:X}"

        # Section parsing
        sec_start = pe_offset + 24 + size_optional_header
        with open(self.file_path, "rb") as f:
            f.seek(sec_start)
            sec_data = f.read(num_sections * 40)

        for i in range(num_sections):
            offset = i * 40
            if offset + 40 > len(sec_data):
                break
            name_raw = sec_data[offset:offset+8].rstrip(b"\x00")
            name = name_raw.decode("latin1", errors="replace")
            vsize = struct.unpack_from("<I", sec_data, offset + 8)[0]
            vaddr = struct.unpack_from("<I", sec_data, offset + 12)[0]
            raw_size = struct.unpack_from("<I", sec_data, offset + 16)[0]
            raw_ptr = struct.unpack_from("<I", sec_data, offset + 20)[0]
            characteristics = struct.unpack_from("<I", sec_data, offset + 36)[0]

            sec_entropy = 0.0
            if raw_size > 0:
                if raw_ptr + raw_size > self.file_size:
                    self.results["anomalies"].append(
                        f"Section {name} raw data points beyond file boundaries (pointer 0x{raw_ptr:X}, size 0x{raw_size:X}, file size 0x{self.file_size:X})"
                    )
                else:
                    with open(self.file_path, "rb") as f:
                        f.seek(raw_ptr)
                        s_bytes = f.read(min(raw_size, 1024 * 512))
                        sec_entropy = calculate_entropy(s_bytes)

            is_executable = bool(characteristics & 0x20000000)
            is_writable = bool(characteristics & 0x80000000)

            # Detect anomalies
            if is_executable and is_writable:
                self.results["anomalies"].append(f"Section {name} is Writable and Executable (W+X) - potential unpacker / shellcode")
            if raw_size == 0 and vsize > 0x1000:
                self.results["anomalies"].append(f"Section {name} has zero disk size but {vsize} bytes virtual size")

            self.results["sections"].append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": f"0x{vaddr:X}",
                "raw_size": raw_size,
                "entropy": sec_entropy,
                "executable": is_executable,
                "writable": is_writable
            })

    def _parse_rich_header(self, header: bytes, pe_offset: int):
        """Parses MSVC Rich Header (compiler product IDs and telemetry)."""
        limit = min(pe_offset, len(header), 4096)
        stub = header[:limit]
        rich_idx = stub.find(b"Rich")
        if rich_idx == -1 or rich_idx + 8 > len(stub):
            return

        xor_key = struct.unpack_from("<I", stub, rich_idx + 4)[0]
        # Search backward for DanS xor'd with xor_key
        dans_magic = struct.pack("<I", 0x536E6144 ^ xor_key) # "DanS"
        dans_idx = stub.rfind(dans_magic, 0, rich_idx)
        if dans_idx == -1:
            return

        # Entry records are 8 bytes each between dans_idx + 16 (after padding) and rich_idx
        prod_map = {
            0x00EB: "VS2015 Resource Compiler",
            0x00FF: "VS2015 C++ Compiler",
            0x0102: "VS2017 Linker",
            0x0103: "VS2017 C++ Compiler",
            0x0104: "VS2019/VS2022 C++ Compiler",
            0x0105: "VS2019/VS2022 Linker",
            0x0107: "VS2019/VS2022 MASM",
            0x0014: "VS2010 C++ Compiler",
            0x001A: "VS2012 C++ Compiler",
            0x00DE: "VS2013 C++ Compiler"
        }

        entry_start = dans_idx + 16
        while entry_start + 8 <= rich_idx:
            comp_id_enc = struct.unpack_from("<I", stub, entry_start)[0]
            count_enc = struct.unpack_from("<I", stub, entry_start + 4)[0]
            comp_id = comp_id_enc ^ xor_key
            count = count_enc ^ xor_key

            prod_id = (comp_id >> 16) & 0xFFFF
            build_id = comp_id & 0xFFFF
            tool_name = prod_map.get(prod_id, f"Tool_0x{prod_id:04X}")

            self.results["rich_header"].append({
                "product_id": f"0x{prod_id:04X}",
                "build_id": build_id,
                "tool": tool_name,
                "count": count
            })
            entry_start += 8

        if self.results["rich_header"]:
            if "MSVC Toolchain (Rich Header Verified)" not in self.results["runtimes"]:
                self.results["runtimes"].append("MSVC Toolchain (Rich Header Verified)")

    def _parse_elf(self, header: bytes):
        self.results["format"] = "ELF (Executable and Linkable Format)"
        if len(header) < 52:
            return
        ei_class = header[4]
        ei_data = header[5]
        self.results["endianness"] = "little" if ei_data == 1 else "big"
        fmt = "<" if ei_data == 1 else ">"

        elf_machines = {
            0x03: "x86",
            0x3E: "x64 (x86_64)",
            0x28: "ARM",
            0xB7: "AArch64 (ARM64)",
            0xF3: "RISC-V"
        }

        if ei_class == 1:
            self.results["format"] = "ELF32"
            machine = struct.unpack_from(f"{fmt}H", header, 18)[0]
            entry = struct.unpack_from(f"{fmt}I", header, 24)[0]
            shoff = struct.unpack_from(f"{fmt}I", header, 32)[0]
            shentsize = struct.unpack_from(f"{fmt}H", header, 46)[0]
            shnum = struct.unpack_from(f"{fmt}H", header, 48)[0]
            shstrndx = struct.unpack_from(f"{fmt}H", header, 50)[0]
            self.results["entry_point"] = f"0x{entry:X}"
        else:
            self.results["format"] = "ELF64"
            if len(header) < 64:
                return
            machine = struct.unpack_from(f"{fmt}H", header, 18)[0]
            entry = struct.unpack_from(f"{fmt}Q", header, 24)[0]
            shoff = struct.unpack_from(f"{fmt}Q", header, 40)[0]
            shentsize = struct.unpack_from(f"{fmt}H", header, 58)[0]
            shnum = struct.unpack_from(f"{fmt}H", header, 60)[0]
            shstrndx = struct.unpack_from(f"{fmt}H", header, 62)[0]
            self.results["entry_point"] = f"0x{entry:X}"

        self.results["architecture"] = elf_machines.get(machine, f"ELF Machine 0x{machine:02X}")

        # Parse ELF Sections if present
        if shoff > 0 and shnum > 0 and shentsize > 0 and shoff + (shnum * shentsize) <= self.file_size:
            try:
                with open(self.file_path, "rb") as f:
                    f.seek(shoff)
                    sh_data = f.read(shnum * shentsize)

                    shstrtab = b""
                    if shstrndx < shnum:
                        str_offset = shstrndx * shentsize
                        if ei_class == 1 and str_offset + 24 <= len(sh_data):
                            tab_off = struct.unpack_from(f"{fmt}I", sh_data, str_offset + 16)[0]
                            tab_sz = struct.unpack_from(f"{fmt}I", sh_data, str_offset + 20)[0]
                        elif ei_class == 2 and str_offset + 40 <= len(sh_data):
                            tab_off = struct.unpack_from(f"{fmt}Q", sh_data, str_offset + 24)[0]
                            tab_sz = struct.unpack_from(f"{fmt}Q", sh_data, str_offset + 32)[0]
                        else:
                            tab_off, tab_sz = 0, 0
                        if tab_off > 0 and tab_off + tab_sz <= self.file_size:
                            f.seek(tab_off)
                            shstrtab = f.read(min(tab_sz, 64 * 1024))

                    for i in range(shnum):
                        s_off = i * shentsize
                        if ei_class == 1:
                            name_idx = struct.unpack_from(f"{fmt}I", sh_data, s_off)[0]
                            flags = struct.unpack_from(f"{fmt}I", sh_data, s_off + 8)[0]
                            vaddr = struct.unpack_from(f"{fmt}I", sh_data, s_off + 12)[0]
                            offset_p = struct.unpack_from(f"{fmt}I", sh_data, s_off + 16)[0]
                            size_p = struct.unpack_from(f"{fmt}I", sh_data, s_off + 20)[0]
                        else:
                            name_idx = struct.unpack_from(f"{fmt}I", sh_data, s_off)[0]
                            flags = struct.unpack_from(f"{fmt}Q", sh_data, s_off + 8)[0]
                            vaddr = struct.unpack_from(f"{fmt}Q", sh_data, s_off + 16)[0]
                            offset_p = struct.unpack_from(f"{fmt}Q", sh_data, s_off + 24)[0]
                            size_p = struct.unpack_from(f"{fmt}Q", sh_data, s_off + 32)[0]

                        sec_name = ""
                        if shstrtab and name_idx < len(shstrtab):
                            null_p = shstrtab.find(b"\x00", name_idx)
                            sec_name = shstrtab[name_idx:null_p if null_p != -1 else None].decode("latin1", errors="replace")
                        if not sec_name:
                            sec_name = f"elf_sec_{i}"

                        sec_entropy = 0.0
                        if size_p > 0 and offset_p + size_p <= self.file_size:
                            f.seek(offset_p)
                            sec_bytes = f.read(min(size_p, 512 * 1024))
                            sec_entropy = calculate_entropy(sec_bytes)

                        is_writable = bool(flags & 0x1) # SHF_WRITE
                        is_executable = bool(flags & 0x4) # SHF_EXECINSTR

                        if is_writable and is_executable:
                            self.results["anomalies"].append(f"ELF Section {sec_name} is Writable and Executable (W+X) - potential unpacker / shellcode")

                        self.results["sections"].append({
                            "name": sec_name,
                            "virtual_size": size_p,
                            "virtual_address": f"0x{vaddr:X}",
                            "raw_size": size_p,
                            "entropy": sec_entropy,
                            "executable": is_executable,
                            "writable": is_writable
                        })
            except Exception:
                pass

    def _parse_macho(self, header: bytes):
        self.results["format"] = "Mach-O"
        if len(header) < 8:
            return
        magic = struct.unpack(">I", header[:4])[0]

        macho_arch_map = {
            0x00000007: "x86 (32-bit)",
            0x01000007: "x64 (x86_64)",
            0x0000000C: "ARM (32-bit)",
            0x0100000C: "ARM64 (AArch64)",
            0x0200000C: "ARM64_32",
            0x00000012: "PowerPC",
            0x01000012: "PowerPC 64"
        }

        if magic in (0xFEEDFACE, 0xCEFAEDFE):
            self.results["format"] = "Mach-O 32-bit"
            endian = ">" if magic == 0xFEEDFACE else "<"
            self.results["endianness"] = "big" if endian == ">" else "little"
            cputype = struct.unpack(f"{endian}I", header[4:8])[0]
            self.results["architecture"] = macho_arch_map.get(cputype, f"Mach-O CPU 0x{cputype:08X}")
        elif magic in (0xFEEDFACF, 0xCFFAEDFE):
            self.results["format"] = "Mach-O 64-bit"
            endian = ">" if magic == 0xFEEDFACF else "<"
            self.results["endianness"] = "big" if endian == ">" else "little"
            cputype = struct.unpack(f"{endian}I", header[4:8])[0]
            self.results["architecture"] = macho_arch_map.get(cputype, f"Mach-O CPU 0x{cputype:08X}")
        elif magic in (0xCAFEBABE, 0xBEBAFECA):
            minor = struct.unpack(">H", header[4:6])[0]
            major = struct.unpack(">H", header[6:8])[0]
            if minor == 0 and 45 <= major <= 75:
                self.results["format"] = f"Java Class Bytecode (v{major}.{minor})"
                self.results["architecture"] = "JVM Bytecode"
                self.results["runtimes"].append("Java Virtual Machine (JVM)")
                return

            self.results["format"] = "Mach-O Universal (Fat Binary)"
            endian = ">" if magic == 0xCAFEBABE else "<"
            self.results["endianness"] = "big" if endian == ">" else "little"
            nfat = struct.unpack(f"{endian}I", header[4:8])[0]
            archs = []
            if nfat <= 20 and len(header) >= 8 + nfat * 20:
                for idx in range(nfat):
                    arch_off = 8 + idx * 20
                    cpu = struct.unpack(f"{endian}I", header[arch_off:arch_off+4])[0]
                    arch_name = macho_arch_map.get(cpu, f"0x{cpu:08X}")
                    archs.append(arch_name)
            self.results["architecture"] = f"Multi-Arch ({', '.join(archs)})" if archs else "Universal (Fat Binary)"

    def _scan_runtimes_and_engines(self, data: bytes):
        # 1. Game Engines
        if b"FNamePool" in data or b"GUObjectArray" in data or b"/Script/Engine" in data or b"UE4Game" in data or b"UE5Game" in data:
            ue_ver = "UE5" if (b"UE5Game" in data or b"UnrealEngine5" in data) else "UE4"
            self.results["game_engine"] = f"Unreal Engine ({ue_ver})"
            self.results["runtimes"].append(f"Unreal Engine ({ue_ver}) Native")

        if b"GameAssembly.dll" in data or b"il2cpp_init" in data or b"il2cpp_domain_get" in data or b"il2cpp" in data:
            self.results["game_engine"] = "Unity (IL2CPP)"
            self.results["runtimes"].append("Unity IL2CPP AOT")
        elif b"mono-2.0-bdwgc.dll" in data or b"Assembly-CSharp.dll" in data or b"UnityEngine.CoreModule" in data:
            self.results["game_engine"] = "Unity (Mono)"
            self.results["runtimes"].append("Unity Mono C#")

        if b"GodotEngine" in data or b"GDScript" in data or b"godot_core" in data or b"GDExtension" in data:
            self.results["game_engine"] = "Godot Engine"
            self.results["runtimes"].append("Godot GDScript / GDExtension")

        # 2. Desktop Frameworks & Web Runtimes
        if b"electron.asar" in data or b"ELECTRON_RUN_AS_NODE" in data or (b"v8::Isolate" in data and b"node" in data):
            self.results["runtimes"].append("Electron / Node.js Runtime")
        if b"tauri" in data and (b"tao::" in data or b"wry::" in data or b"tauri::ipc" in data or b"__TAURI__" in data):
            self.results["runtimes"].append("Tauri Desktop (Rust + WebView)")

        # 3. .NET Ecosystem
        if b"RhpCreateTypeMesh" in data or b"RhpReversePInvoke2" in data or b"System.Private.CoreLib" in data:
            self.results["runtimes"].append(".NET NativeAOT (Pre-compiled Native)")
        elif b"coreclr.dll" in data or b"hostfxr.dll" in data:
            self.results["runtimes"].append(".NET Core / .NET 5-10 AppHost")
        elif b"mscoree.dll" in data or b"_CorExeMain" in data or b"_CorDllMain" in data:
            self.results["runtimes"].append(".NET Framework / CLR Managed")

        # 4. Python Bundlers
        if b"_MEI" in data or b"MEIPASS" in data or b"pyi-windows-sleep" in data:
            self.results["runtimes"].append("Python (PyInstaller Bundle)")
        elif b"py2exe" in data:
            self.results["runtimes"].append("Python (py2exe Bundle)")

        # 5. Native Toolchains
        if b"MSVCP" in data or b"VCRUNTIME" in data or b"Microsoft Visual Studio" in data:
            self.results["runtimes"].append("MSVC C/C++ Runtime")
        if b"libstdc++" in data or b"GCC: (" in data:
            self.results["runtimes"].append("GCC (GNU C++)")
        if b"clang version" in data or b"libc++" in data:
            self.results["runtimes"].append("LLVM / Clang")
        if b"rust_panic" in data or b"core::panicking" in data:
            self.results["runtimes"].append("Rust Native Runtime")
        if b"runtime.goexit" in data or b"runtime.main" in data:
            self.results["runtimes"].append("Go (Golang Runtime)")

        # De-duplicate runtimes
        self.results["runtimes"] = sorted(list(set(self.results["runtimes"])))

    def _evaluate_protections(self):
        # Section name heuristics
        known_packers = {
            ".upx": "UPX Packer",
            "UPX0": "UPX Packer",
            "UPX1": "UPX Packer",
            ".vmp": "VMProtect Virtual Machine",
            ".themida": "Themida / WinLicense Protector",
            ".enigma": "Enigma Protector",
            ".aspack": "ASPack",
            ".mpress": "MPRESS",
            "PELOCK": "PELock"
        }
        for sec in self.results["sections"]:
            name = sec["name"]
            for sig, label in known_packers.items():
                if sig.lower() in name.lower():
                    if label not in self.results["packers_and_protections"]:
                        self.results["packers_and_protections"].append(label)

        # High entropy threshold check
        if self.results["entropy_total"] >= 7.3:
            indicator = f"High Overall Entropy ({self.results['entropy_total']}/8.0) - Likely Compressed / Encrypted / Packed"
            if indicator not in self.results["packers_and_protections"]:
                self.results["packers_and_protections"].append(indicator)

        # Anti-analysis heuristics
        anti_apis = [
            b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess",
            b"OutputDebugStringA", b"OutputDebugStringW", b"QueryPerformanceCounter"
        ]
        with open(self.file_path, "rb") as f:
            sample = f.read(min(self.file_size, 5 * 1024 * 1024))
            for api in anti_apis:
                if api in sample:
                    name = api.decode("ascii")
                    if name not in self.results["anti_analysis"]:
                        self.results["anti_analysis"].append(name)

def format_text_report(res: Dict[str, Any]) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f" APEX-RE TRIAGE REPORT : {res['file']}")
    lines.append("=" * 72)
    lines.append(f"  Format        : {res['format']}")
    lines.append(f"  Architecture  : {res['architecture']}")
    lines.append(f"  File Size     : {res['size_bytes']:,} bytes")
    lines.append(f"  Total Entropy : {res['entropy_total']} / 8.0000")
    if res.get("entry_point"):
        lines.append(f"  Entry Point   : {res['entry_point']}")
    if res.get("game_engine"):
        lines.append(f"  Game Engine   : {res['game_engine']}")
    lines.append(f"  Runtimes      : {', '.join(res['runtimes']) if res['runtimes'] else 'Pure Native / Unidentified'}")
    lines.append(f"  Protections   : {', '.join(res['packers_and_protections']) if res['packers_and_protections'] else 'None Detected'}")
    if res.get("anti_analysis"):
        lines.append(f"  Anti-Analysis : {', '.join(res['anti_analysis'])}")
    if res.get("rich_header"):
        tools = [f"{t['tool']} (b{t['build_id']}, count:{t['count']})" for t in res["rich_header"][:4]]
        lines.append(f"  Rich Header   : {', '.join(tools)}")

    if res["sections"]:
        lines.append("-" * 72)
        lines.append("  SECTIONS TABLE:")
        lines.append(f"  {'Name':<10} {'VirtAddr':<12} {'VirtSize':<10} {'RawSize':<10} {'Entropy':<8} {'Flags'}")
        for s in res["sections"]:
            flags = []
            if s["executable"]: flags.append("X")
            if s["writable"]: flags.append("W")
            lines.append(f"  {s['name']:<10} {s['virtual_address']:<12} {s['virtual_size']:<10} {s['raw_size']:<10} {s['entropy']:<8.4f} {'+'.join(flags) if flags else 'R'}")

    if res["anomalies"]:
        lines.append("-" * 72)
        lines.append("  ANOMALIES / ALERTS:")
        for a in res["anomalies"]:
            lines.append(f"  [!] {a}")
    lines.append("=" * 72)
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Apex-RE Binary Triage and Runtime Analysis Utility")
    parser.add_argument("target", help="Path to binary executable, library, or package")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    parser.add_argument("--summary", action="store_true", help="Print single-line summary string")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        sys.stderr.write(f"Error: Target file not found: {args.target}\n")
        sys.exit(1)

    triager = BinaryTriager(args.target)
    results = triager.analyze()

    if args.json:
        print(json.dumps(results, indent=2))
    elif args.summary:
        eng = f" [{results['game_engine']}]" if results.get("game_engine") else ""
        rts = f" ({', '.join(results['runtimes'])})" if results["runtimes"] else ""
        print(f"{results['file']}: {results['format']} {results['architecture']}{eng}{rts} Entropy:{results['entropy_total']}")
    else:
        print(format_text_report(results))

if __name__ == "__main__":
    main()
