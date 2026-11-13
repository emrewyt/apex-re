#!/usr/bin/env python3
"""
Unit Test Suite for Apex-RE Core Analysis Scripts.
Covers apex_triage.py, memory_diff.py, kaitai_synth.py, and unflatten_trace.py.
"""

import unittest
import os
import sys
import tempfile
import struct
import json

# Ensure scripts directory is on Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(os.path.dirname(CURRENT_DIR), "skills", "apex-re", "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from apex_triage import BinaryTriager, calculate_entropy, format_text_report
from memory_diff import MemoryDiffer
from kaitai_synth import KaitaiSynthesizer
from unflatten_trace import ControlFlowUnflattener
from sig_scan import PatternScanner
from vm_analyzer import VMAnalyzer

class TestApexTriage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_entropy_calculation(self):
        # Uniform zero bytes should have 0.0 entropy
        zeros = b"\x00" * 1024
        self.assertEqual(calculate_entropy(zeros), 0.0)

        # Equal distribution of all 256 bytes should have 8.0 entropy
        all_bytes = bytes(range(256)) * 4
        self.assertAlmostEqual(calculate_entropy(all_bytes), 8.0, places=3)

    def test_pe_parsing_and_runtime_detection(self):
        pe_path = os.path.join(self.temp_dir.name, "sample.exe")
        # Build synthetic PE32+ header
        dos_header = bytearray(0x80)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x40) # PE offset at 0x40

        opt_size = 0xF0
        pe_header = bytearray(24 + opt_size)
        pe_header[0:4] = b"PE\x00\x00"
        struct.pack_into("<H", pe_header, 4, 0x8664) # x64 machine
        struct.pack_into("<H", pe_header, 6, 2)      # 2 sections
        struct.pack_into("<H", pe_header, 20, opt_size)  # size of opt header

        # Optional header (PE32+)
        struct.pack_into("<H", pe_header, 24, 0x20B) # PE32+ magic
        struct.pack_into("<I", pe_header, 40, 0x1000) # Entry point

        # Sections table
        sec1 = bytearray(40)
        sec1[0:6] = b".text\x00"
        struct.pack_into("<I", sec1, 8, 0x1000)  # VirtualSize
        struct.pack_into("<I", sec1, 12, 0x1000) # VirtualAddress
        struct.pack_into("<I", sec1, 16, 0x400)  # SizeOfRawData
        struct.pack_into("<I", sec1, 20, 0x200)  # PointerToRawData
        struct.pack_into("<I", sec1, 36, 0x60000020) # Read + Execute

        sec2 = bytearray(40)
        sec2[0:6] = b".vmp0\x00" # Known VMProtect section name
        struct.pack_into("<I", sec2, 8, 0x2000)
        struct.pack_into("<I", sec2, 12, 0x2000)
        struct.pack_into("<I", sec2, 16, 0x800)
        struct.pack_into("<I", sec2, 20, 0x600)
        struct.pack_into("<I", sec2, 36, 0xE0000020) # Writable + Executable (W+X)

        full_binary = dos_header[:0x40] + pe_header + sec1 + sec2
        # Pad to section offsets
        full_binary += b"\x00" * (0x600 + 0x800 - len(full_binary) + 100)
        # Add payload with signatures: Unreal FNamePool, NativeAOT, and Unity
        payload = b"FNamePool /Script/Engine GameAssembly.dll RhpCreateTypeMesh" + b"\x90" * 2000
        full_binary += payload

        with open(pe_path, "wb") as f:
            f.write(full_binary)

        triager = BinaryTriager(pe_path)
        res = triager.analyze()

        self.assertEqual(res["format"], "PE32+ (64-bit)")
        self.assertEqual(res["architecture"], "x64 (AMD64 / 64-bit)")
        self.assertEqual(res["entry_point"], "0x1000")
        self.assertIn("Unreal Engine (UE4) Native", res["runtimes"])
        self.assertIn("Unity IL2CPP AOT", res["runtimes"])
        self.assertIn(".NET NativeAOT (Pre-compiled Native)", res["runtimes"])
        self.assertIn("VMProtect Virtual Machine", res["packers_and_protections"])
        self.assertTrue(any("W+X" in a for a in res["anomalies"]))

        report_txt = format_text_report(res)
        self.assertIn("APEX-RE TRIAGE REPORT", report_txt)

    def test_elf_parsing(self):
        elf_path = os.path.join(self.temp_dir.name, "sample.elf")
        elf_hdr = bytearray(64)
        elf_hdr[0:4] = b"\x7fELF"
        elf_hdr[4] = 2 # ELF64
        elf_hdr[5] = 1 # Little endian
        struct.pack_into("<H", elf_hdr, 18, 0x3E) # x86_64
        struct.pack_into("<Q", elf_hdr, 24, 0x401000) # Entry

        with open(elf_path, "wb") as f:
            f.write(elf_hdr + b"core::panicking") # Rust runtime signature

        triager = BinaryTriager(elf_path)
        res = triager.analyze()
        self.assertEqual(res["format"], "ELF64")
        self.assertEqual(res["architecture"], "x64 (x86_64)")
        self.assertEqual(res["entry_point"], "0x401000")
        self.assertIn("Rust Native Runtime", res["runtimes"])

    def test_additional_runtime_formats(self):
        # 1. Godot PCK
        pck_path = os.path.join(self.temp_dir.name, "game.pck")
        with open(pck_path, "wb") as f:
            f.write(b"GDPC\x01\x00\x00\x00" + b"GodotEngine GDScript" * 10)
        t_pck = BinaryTriager(pck_path).analyze()
        self.assertEqual(t_pck["format"], "Godot PCK Package")
        self.assertEqual(t_pck["game_engine"], "Godot Engine")

        # 2. WASM
        wasm_path = os.path.join(self.temp_dir.name, "module.wasm")
        with open(wasm_path, "wb") as f:
            f.write(b"\x00asm\x01\x00\x00\x00")
        t_wasm = BinaryTriager(wasm_path).analyze()
        self.assertEqual(t_wasm["format"], "WebAssembly (WASM)")
        self.assertEqual(t_wasm["architecture"], "WASM v1")

        # 3. Electron / Tauri
        elec_path = os.path.join(self.temp_dir.name, "app.bin")
        with open(elec_path, "wb") as f:
            f.write(b"electron.asar ELECTRON_RUN_AS_NODE")
        t_elec = BinaryTriager(elec_path).analyze()
        self.assertIn("Electron / Node.js Runtime", t_elec["runtimes"])

        tauri_path = os.path.join(self.temp_dir.name, "tauri_app.bin")
        with open(tauri_path, "wb") as f:
            f.write(b"tauri wry:: tao:: tauri::ipc")
        t_tauri = BinaryTriager(tauri_path).analyze()
        self.assertIn("Tauri Desktop (Rust + WebView)", t_tauri["runtimes"])

        # 4. PyInstaller
        py_path = os.path.join(self.temp_dir.name, "python_app.bin")
        with open(py_path, "wb") as f:
            f.write(b"MEIPASS _MEI pyi-windows-sleep")
        t_py = BinaryTriager(py_path).analyze()
        self.assertIn("Python (PyInstaller Bundle)", t_py["runtimes"])

    def test_macho_and_fat_binary_parsing(self):
        # 1. Single-arch Mach-O 64-bit ARM64
        macho_path = os.path.join(self.temp_dir.name, "arm64_bin")
        with open(macho_path, "wb") as f:
            f.write(struct.pack(">IIII", 0xFEEDFACF, 0x0100000C, 0, 2))
        res_macho = BinaryTriager(macho_path).analyze()
        self.assertEqual(res_macho["format"], "Mach-O 64-bit")
        self.assertIn("ARM64", res_macho["architecture"])

        # 2. Universal Fat Mach-O (x86_64 + ARM64)
        fat_path = os.path.join(self.temp_dir.name, "universal_bin")
        with open(fat_path, "wb") as f:
            f.write(struct.pack(">II", 0xCAFEBABE, 2))
            f.write(struct.pack(">IIIII", 0x01000007, 3, 0x1000, 0x1000, 12))
            f.write(struct.pack(">IIIII", 0x0100000C, 0, 0x2000, 0x1000, 14))
        res_fat = BinaryTriager(fat_path).analyze()
        self.assertEqual(res_fat["format"], "Mach-O Universal (Fat Binary)")
        self.assertIn("x64", res_fat["architecture"])
        self.assertIn("ARM64", res_fat["architecture"])

        # 3. Java class CA FE BA BE disambiguation
        java_path = os.path.join(self.temp_dir.name, "Sample.class")
        with open(java_path, "wb") as f:
            f.write(struct.pack(">IHH", 0xCAFEBABE, 0, 61)) # Java 17 bytecode
        res_java = BinaryTriager(java_path).analyze()
        self.assertIn("Java Class Bytecode", res_java["format"])
        self.assertEqual(res_java["architecture"], "JVM Bytecode")

    def test_pe_out_of_bounds_section_anomaly(self):
        pe_path = os.path.join(self.temp_dir.name, "corrupt.exe")
        dos = bytearray(0x40)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x40)

        pe = bytearray(24)
        pe[0:4] = b"PE\x00\x00"
        struct.pack_into("<H", pe, 4, 0x8664) # x64
        struct.pack_into("<H", pe, 6, 1)      # 1 section
        struct.pack_into("<H", pe, 20, 0)     # no optional header

        sec = bytearray(40)
        sec[0:5] = b".evil"
        struct.pack_into("<I", sec, 8, 0x1000)
        struct.pack_into("<I", sec, 12, 0x1000)
        struct.pack_into("<I", sec, 16, 0x5000) # raw size 20KB
        struct.pack_into("<I", sec, 20, 0x1000) # raw ptr 4KB, but file is < 200 bytes

        with open(pe_path, "wb") as f:
            f.write(dos + pe + sec)

        res = BinaryTriager(pe_path).analyze()
        self.assertTrue(any("beyond file boundaries" in a for a in res["anomalies"]))

    def test_elf_sections_and_anomalies(self):
        elf_path = os.path.join(self.temp_dir.name, "test_sec.elf")
        hdr = bytearray(64)
        hdr[0:4] = b"\x7fELF"
        hdr[4] = 2 # 64-bit
        hdr[5] = 1 # little-endian
        struct.pack_into("<H", hdr, 18, 0x3E) # x86_64
        struct.pack_into("<Q", hdr, 24, 0x400000) # entry
        struct.pack_into("<Q", hdr, 40, 64) # e_shoff at offset 64
        struct.pack_into("<H", hdr, 58, 64) # e_shentsize = 64
        struct.pack_into("<H", hdr, 60, 2)  # e_shnum = 2 sections
        struct.pack_into("<H", hdr, 62, 0)  # shstrndx = 0

        # Section 0: null section
        sec0 = bytearray(64)
        # Section 1: executable + writable section (W+X)
        sec1 = bytearray(64)
        struct.pack_into("<I", sec1, 0, 0)     # sh_name
        struct.pack_into("<I", sec1, 4, 1)     # sh_type: SHT_PROGBITS
        struct.pack_into("<Q", sec1, 8, 0x5)   # sh_flags: SHF_WRITE (0x1) | SHF_EXECINSTR (0x4)
        struct.pack_into("<Q", sec1, 16, 0x500000) # sh_addr
        struct.pack_into("<Q", sec1, 24, 192)  # sh_offset
        struct.pack_into("<Q", sec1, 32, 64)   # sh_size

        payload = b"\x90" * 64
        with open(elf_path, "wb") as f:
            f.write(hdr + sec0 + sec1 + payload)

        res = BinaryTriager(elf_path).analyze()
        self.assertEqual(len(res["sections"]), 2)
        self.assertTrue(any("W+X" in a for a in res["anomalies"]))

class TestMemoryDiff(unittest.TestCase):
    def test_memory_diffing_and_struct_synthesis(self):
        # 64 bytes memory snapshot
        buf_a = bytearray(64)
        buf_b = bytearray(64)

        # Offset 0x04: int32 changed from 100 to 250
        struct.pack_into("<i", buf_a, 0x04, 100)
        struct.pack_into("<i", buf_b, 0x04, 250)

        # Offset 0x0C: float32 changed from 1.0 to 2.5
        struct.pack_into("<f", buf_a, 0x0C, 1.0)
        struct.pack_into("<f", buf_b, 0x0C, 2.5)

        # Offset 0x18: 64-bit pointer
        struct.pack_into("<Q", buf_a, 0x18, 0x00007FF710000000)
        struct.pack_into("<Q", buf_b, 0x18, 0x00007FF720000000)

        differ = MemoryDiffer(bytes(buf_a), bytes(buf_b), base_addr=0x140000000, alignment=4)
        diffs = differ.compute_diffs()

        self.assertGreaterEqual(len(diffs), 3)

        # Check interpretations
        d_int = next(d for d in diffs if d["offset"] == 0x04)
        self.assertEqual(d_int["interpretations"]["i32"]["before"], 100)
        self.assertEqual(d_int["interpretations"]["i32"]["after"], 250)
        self.assertEqual(d_int["interpretations"]["i32"]["delta"], 150)

        # Synthesize C++ and C# structs
        structs = differ.synthesize_struct("PlayerEntity")
        self.assertIn("struct PlayerEntity {", structs["cpp"])
        self.assertIn("int32_t field_0x0004;", structs["cpp"])
        self.assertIn("float field_0x000C;", structs["cpp"])
        self.assertIn("uintptr_t field_0x0018;", structs["cpp"])
        self.assertIn("[StructLayout(LayoutKind.Explicit)]", structs["csharp"])
        self.assertIn("[FieldOffset(0x4)] public int field_0x0004;", structs["csharp"])
        self.assertIn("[FieldOffset(0xC)] public float field_0x000C;", structs["csharp"])
        self.assertIn("[FieldOffset(0x18)] public IntPtr field_0x0018;", structs["csharp"])

    def test_identical_memory_buffers(self):
        buf = b"\xAA" * 128
        differ = MemoryDiffer(buf, buf, base_addr=0x1000)
        diffs = differ.compute_diffs()
        self.assertEqual(len(diffs), 0)

class TestKaitaiSynth(unittest.TestCase):
    def test_kaitai_synthesis(self):
        # Binary data: ASCII magic "PKT1" + uint32 length + float + null-terminated string
        raw = bytearray()
        raw.extend(b"PKT1")
        raw.extend(struct.pack("<I", 42))
        raw.extend(struct.pack("<f", 3.1415))
        raw.extend(b"HeroName\x00")
        raw.extend(b"\x01\x02\x03\x04")

        synth = KaitaiSynthesizer(bytes(raw), struct_id="packet_header", endian="le")
        ksy = synth.synthesize()

        self.assertIn("id: packet_header", ksy)
        self.assertIn("endian: le", ksy)
        self.assertIn("contents: \"PKT1\"", ksy)
        self.assertIn("type: u4", ksy)
        self.assertIn("type: f4", ksy)
        self.assertIn("type: strz", ksy)

    def test_kaitai_with_u64_and_u4(self):
        # Test distinguishing true 64-bit integer (> 0xFFFFFFFF) from two 32-bit integers
        raw = bytearray()
        raw.extend(b"TEST") # 4 bytes
        raw.extend(struct.pack("<I", 100)) # 4 bytes -> now at offset 8 (aligned to 8)
        # At offset 8: true 64-bit value: 0x00007FF710000000
        raw.extend(struct.pack("<Q", 0x00007FF710000000))
        # At offset 16: two 32-bit integers (not collapsed into 64-bit)
        raw.extend(struct.pack("<I", 500))
        raw.extend(struct.pack("<I", 600))

        synth = KaitaiSynthesizer(bytes(raw), struct_id="data_payload", endian="le")
        ksy = synth.synthesize()
        self.assertIn("type: u8", ksy)
        self.assertIn("type: u4", ksy)

class TestUnflattenTrace(unittest.TestCase):
    def test_unflattening_from_json(self):
        trace_json = json.dumps([
            {"state": 1, "block": "BB_INIT", "code": "int counter = 0", "next_state": 2},
            {"state": 2, "block": "BB_LOOP", "code": "counter += 1", "next_state": 3},
            {"state": 3, "block": "BB_CHECK", "code": "/* check */", "next_state": 4},
            {"state": 4, "block": "BB_EXIT", "code": "return counter", "next_state": None}
        ])

        unflattener = ControlFlowUnflattener.from_json(trace_json)
        unflattener.analyze()

        self.assertEqual(unflattener.entry_state, 1)
        self.assertIn(4, unflattener.terminal_states)

        c_code = unflattener.reconstruct_c_code()
        self.assertIn("void reconstructed_function()", c_code)
        self.assertIn("int counter = 0;", c_code)
        self.assertIn("counter += 1;", c_code)

        mermaid = unflattener.generate_mermaid()
        self.assertIn("flowchart TD", mermaid)
        self.assertIn("node_1", mermaid)
        self.assertIn("node_2", mermaid)

    def test_unflattening_from_text(self):
        log_text = """
        State: 0x10 -> Block: BB_START -> Code: 'x = 10;' -> Next: 0x20
        State: 0x20 -> Block: BB_END -> Code: 'return x;' -> Next: exit
        """
        unflattener = ControlFlowUnflattener.from_text_log(log_text)
        unflattener.analyze()
        self.assertEqual(unflattener.entry_state, 0x10)
        c_code = unflattener.reconstruct_c_code()
        self.assertIn("x = 10;", c_code)
        self.assertIn("return x;", c_code)

    def test_unflattening_branching_and_loops(self):
        # State machine with conditional branching and loop back-edge
        trace = [
            {"state": 10, "block": "BB_ENTRY", "code": "int i = 0;", "next_state": 20},
            {"state": 20, "block": "BB_COND", "code": "", "successors": [(30, "i < 10"), (40, "i >= 10")]},
            {"state": 30, "block": "BB_BODY", "code": "i++;", "next_state": 20}, # loop back-edge to 20
            {"state": 40, "block": "BB_DONE", "code": "return i;", "next_state": None}
        ]
        # Register in custom format
        unflattener = ControlFlowUnflattener([])
        unflattener.entry_state = 10
        unflattener.state_handlers = {
            10: {"block": "BB_ENTRY", "code": "int i = 0;", "successors": [(20, None)]},
            20: {"block": "BB_COND", "code": "", "successors": [(30, "i < 10"), (40, "i >= 10")]},
            30: {"block": "BB_BODY", "code": "i++;", "successors": [(20, None)]},
            40: {"block": "BB_DONE", "code": "return i;", "successors": []}
        }
        c_code = unflattener.reconstruct_c_code()
        # Verify labels exist
        self.assertIn("state_0x14:", c_code) # state 20
        self.assertIn("state_0x1E:", c_code) # state 30
        self.assertIn("state_0x28:", c_code) # state 40
        # Verify goto targets exist
        self.assertIn("goto state_0x1E;", c_code)
        self.assertIn("goto state_0x28;", c_code)
        self.assertIn("goto state_0x14;", c_code)

class TestPatternScanner(unittest.TestCase):
    def test_ida_pattern_parsing(self):
        pat_str = "48 8B 05 ? ? ? ? 48 85 C0"
        pat, mask = PatternScanner.parse_ida_pattern(pat_str)
        self.assertEqual(len(pat), 10)
        self.assertEqual(len(mask), 10)
        self.assertEqual(pat[0:3], b"\x48\x8B\x05")
        self.assertEqual(mask[0:3], b"\xFF\xFF\xFF")
        self.assertEqual(mask[3:7], b"\x00\x00\x00\x00") # Wildcards
        self.assertEqual(pat[7:10], b"\x48\x85\xC0")
        self.assertEqual(mask[7:10], b"\xFF\xFF\xFF")

    def test_scan_pattern_with_wildcards(self):
        # Buffer containing concrete bytes matching wildcard pattern
        data = b"\x90" * 32 + b"\x48\x8B\x05\x12\x34\x56\x78\x48\x85\xC0" + b"\xCC" * 16
        pat, mask = PatternScanner.parse_ida_pattern("48 8B 05 ? ? ? ? 48 85 C0")
        matches = PatternScanner.scan_pattern(data, pat, mask)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0], 32)

    def test_rip_relative_resolution(self):
        # Instruction: mov rax, [rip + 0x100] at offset 0x20
        # In x64: 48 8B 05 00 01 00 00 (7 bytes, disp at offset +3)
        data = bytearray(0x200)
        data[0x20:0x27] = b"\x48\x8B\x05" + struct.pack("<i", 0x100)
        res = PatternScanner.resolve_rip_relative(bytes(data), match_offset=0x20,
                                                  disp_offset_within_match=3,
                                                  instruction_length=7,
                                                  image_base=0x140000000)
        # Next RIP = 0x20 + 7 = 0x27
        # Target RVA = 0x27 + 0x100 = 0x127
        # Target VA = 0x140000000 + 0x127 = 0x140000127
        self.assertEqual(res["target_rva"], "0x127")
        self.assertEqual(res["target_va"], "0x140000127")

    def test_synthesize_unique_signature(self):
        # Create buffer with random-like unique pattern at offset 0x40
        data = bytearray(b"\x90" * 0x100)
        unique_bytes = b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xD9"
        data[0x40:0x40+len(unique_bytes)] = unique_bytes

        sig_info = PatternScanner.synthesize_unique_signature(bytes(data), target_offset=0x40)
        self.assertIsNotNone(sig_info)
        self.assertTrue(sig_info["unique"])
        self.assertEqual(sig_info["offset"], 0x40)
        self.assertIn("48 89 5C 24 08", sig_info["pattern"])

class TestVMAnalyzer(unittest.TestCase):
    def test_vm_dispatcher_detection_and_slicing(self):
        trace = [
            # Dispatcher loop executing multiple times
            {"address": 0x1000, "mnemonic": "mov", "operands": "rax, [rsi]", "raw": "mov rax, [rsi]"},
            {"address": 0x1003, "mnemonic": "add", "operands": "rsi, 8", "raw": "add rsi, 8"},
            {"address": 0x1007, "mnemonic": "jmp", "operands": "[table + rax*8]", "raw": "jmp [table + rax*8]"},
            # Handler 1: VPUSH
            {"address": 0x2000, "mnemonic": "mov", "operands": "rbx, 0x42", "raw": "mov rbx, 0x42"},
            # Dispatcher loop repeat
            {"address": 0x1000, "mnemonic": "mov", "operands": "rax, [rsi]", "raw": "mov rax, [rsi]"},
            {"address": 0x1003, "mnemonic": "add", "operands": "rsi, 8", "raw": "add rsi, 8"},
            {"address": 0x1007, "mnemonic": "jmp", "operands": "[table + rax*8]", "raw": "jmp [table + rax*8]"},
            # Handler 2: VALU XOR
            {"address": 0x3000, "mnemonic": "xor", "operands": "rbx, 0x55", "raw": "xor rbx, 0x55"},
            # Dispatcher loop repeat
            {"address": 0x1000, "mnemonic": "mov", "operands": "rax, [rsi]", "raw": "mov rax, [rsi]"},
            {"address": 0x1003, "mnemonic": "add", "operands": "rsi, 8", "raw": "add rsi, 8"},
            {"address": 0x1007, "mnemonic": "jmp", "operands": "[table + rax*8]", "raw": "jmp [table + rax*8]"},
            # Exit handler
            {"address": 0x4000, "mnemonic": "mov", "operands": "rax, rbx", "raw": "mov rax, rbx"}
        ]
        analyzer = VMAnalyzer()
        analyzer.trace = trace

        dispatchers = analyzer.detect_dispatcher_loop(min_repetitions=3)
        self.assertIn(0x1000, dispatchers)
        self.assertIn(0x1003, dispatchers)
        self.assertIn(0x1007, dispatchers)

        filtered = analyzer.filter_dispatcher_overhead()
        # Dispatcher instructions should be removed
        filtered_addrs = [e["address"] for e in filtered]
        self.assertNotIn(0x1000, filtered_addrs)
        self.assertIn(0x2000, filtered_addrs)
        self.assertIn(0x3000, filtered_addrs)
        self.assertIn(0x4000, filtered_addrs)

        sliced = analyzer.backward_slice("rax")
        self.assertTrue(len(sliced) >= 2)
        expr = analyzer.synthesize_expression("rax")
        self.assertIn("xor rbx, 0x55", expr)
        self.assertIn("mov rax, rbx", expr)

class TestRichHeaderAndAntiAnalysis(unittest.TestCase):
    def test_pe_rich_header_and_anti_analysis(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Construct PE with Rich Header
            xor_key = 0x12345678
            dos_stub = bytearray(0x100)
            dos_stub[0:2] = b"MZ"
            pe_off = 0x80
            struct.pack_into("<I", dos_stub, 0x3C, pe_off)

            # Insert DanS ... Rich block inside DOS stub
            # DanS at 0x40
            dans_enc = struct.pack("<I", 0x536E6144 ^ xor_key) # "DanS"
            dos_stub[0x40:0x44] = dans_enc
            # 3 zero dwords
            dos_stub[0x44:0x50] = struct.pack("<III", 0 ^ xor_key, 0 ^ xor_key, 0 ^ xor_key)

            # Record 1: Prod 0x0104 (VS2019/VS2022 C++), Build 31332, Count 15
            comp_id_1 = (0x0104 << 16) | 31332
            dos_stub[0x50:0x58] = struct.pack("<II", comp_id_1 ^ xor_key, 15 ^ xor_key)

            # Rich marker at 0x58
            dos_stub[0x58:0x5C] = b"Rich"
            dos_stub[0x5C:0x60] = struct.pack("<I", xor_key)

            # PE Header at 0x80
            pe_hdr = bytearray(0x80)
            pe_hdr[0:4] = b"PE\x00\x00"
            struct.pack_into("<H", pe_hdr, 4, 0x8664) # x64

            # Add payload with anti-debugging API
            payload = b"IsDebuggerPresent CheckRemoteDebuggerPresent"

            with open(tmp_path, "wb") as f:
                f.write(dos_stub[:pe_off] + pe_hdr + payload)

            triager = BinaryTriager(tmp_path)
            res = triager.analyze()

            self.assertTrue(len(res["rich_header"]) > 0)
            self.assertEqual(res["rich_header"][0]["tool"], "VS2019/VS2022 C++ Compiler")
            self.assertEqual(res["rich_header"][0]["build_id"], 31332)
            self.assertEqual(res["rich_header"][0]["count"], 15)

            self.assertIn("IsDebuggerPresent", res["anti_analysis"])
            self.assertIn("CheckRemoteDebuggerPresent", res["anti_analysis"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
