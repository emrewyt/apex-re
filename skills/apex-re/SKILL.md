---
name: apex-re
description: Master-Tier Reverse Engineering Skill for AI Agents. Covers Unreal Engine 4-5, Unity (Mono/IL2CPP), Godot 3-4, .NET 3-10 / NativeAOT, Electron, Tauri, MSVC/CMake C++, and Python. Features autonomous binary triage, differential memory state diffing, Kaitai Struct file format synthesis, OLLVM control flow unflattening, consensus decompilation, and round-trip verification.
---

# Apex-RE: Master-Tier Autonomous Reverse Engineering Agent Guide

You are equipped with **Apex-RE**, an elite reverse engineering capability. Your objective is to deconstruct, analyze, deobfuscate, and reconstruct target software, games, protocols, memory structures, and binary formats into verified, compilable high-level code.

---

## 1. The 5-Layer Master Architecture

When assigned a reverse engineering objective, follow the 5-layer methodology sequentially:

```text
Target Binary / Memory / Process
  │
  ├── [Layer 1] Deep Triage & Classification
  │     Execute: python scripts/apex_triage.py <target>
  │     Identify architecture, compiler, runtime, packing, entropy, and engines.
  │
  ├── [Layer 2] Dynamic Memory & Differential State Analysis
  │     Execute: python scripts/memory_diff.py <dump_before> <dump_after> --struct <Name>
  │     Isolate state mutations, calculate field offsets, and synthesize C++/C# structs.
  │
  ├── [Layer 3] Engine & Runtime Deconstruction
  │     Consult engine-specific references for Unreal, Unity, Godot, .NET, Electron, Tauri, Python.
  │
  ├── [Layer 4] Symbolic Solving & Control Flow Deobfuscation
  │     Execute: python scripts/unflatten_trace.py <trace> --format c
  │     Execute: python scripts/kaitai_synth.py <binary_file> -o <struct.ksy>
  │     Unflatten OLLVM dispatchers, prove opaque predicates, and devirtualize VM handlers.
  │
  └── [Layer 5] Round-Trip Verification Loop
        Compile recovered code, run 1,000 synthetic test vectors against native slice,
        and certify 100% equivalence before delivery.
```

---

## 2. Tooling & Script Execution Guide

The `scripts/` directory contains four zero-dependency Python utilities:

### 2.1 Binary Triage (`scripts/apex_triage.py`)
Analyzes executable formats (PE32/PE32+, ELF, Mach-O, WASM), measures Shannon entropy per section, detects anomalies (W+X permissions, packer signatures), and fingerprints high-level runtimes:
```bash
python scripts/apex_triage.py <binary_path> [--json] [--summary]
```

### 2.2 Differential Memory Differ (`scripts/memory_diff.py`)
Compares two binary memory snapshots (e.g. before and after a user action) to isolate modified variables, compute deltas across primitive data types (int8..int64, float32, float64, pointer), and emit compilable C++ and C# explicit struct definitions:
```bash
python scripts/memory_diff.py <dump_a.bin> <dump_b.bin> --base 0x140000000 --align 4 --struct <StructName>
```

### 2.3 Kaitai Struct Synthesizer (`scripts/kaitai_synth.py`)
Parses binary headers, save games, network packets, or asset containers and autonomously generates a standard Kaitai Struct YAML specification (`.ksy`) for serialization/deserialization:
```bash
python scripts/kaitai_synth.py <input.bin> --id <packet_name> --endian auto -o <spec.ksy>
```

### 2.4 Control Flow Unflattener (`scripts/unflatten_trace.py`)
Deobfuscates OLLVM flattened basic block state machines. Eliminates the central switch dispatcher loop and reconstructs linear C pseudocode or Mermaid flowcharts:
```bash
python scripts/unflatten_trace.py <trace.json_or_log> --format c
```

---

## 3. Targeted Technical Reference Navigation

Always consult the dedicated technical reference corresponding to your target:

| Target Category | Technology / Framework | Specialized Reference File |
| :--- | :--- | :--- |
| **Game Engines** | Unreal Engine 4 & 5 (FNamePool, GUObjectArray, ProcessEvent) | `references/game-engines-unreal-unity.md` |
| **Game Engines** | Unity (Mono C# & IL2CPP GameAssembly.dll, Cpp2IL) | `references/game-engines-unreal-unity.md` |
| **Game Engines** | Godot Engine 3 & 4 (.pck, GDScript bytecode, GDExtension) | `references/godot-engine.md` |
| **Managed & Native Apps** | .NET 3.5 to 10, Single-File Bundles, ReadyToRun, NativeAOT | `references/dotnet-and-nativeaot.md` |
| **Desktop Web Runtimes** | Electron (ASAR unpacking, IPC channels) & Tauri (Rust core, WebView) | `references/desktop-electron-tauri.md` |
| **Native C/C++** | MSVC, CMake, Clang, PE/ELF calling conventions, RTTI, VTables | `references/msvc-cmake-native.md` |
| **Python** | PyInstaller unpacking, .pyc headers, pycdc decompilation, PyArmor | `references/python-bytecodes.md` |
| **Obfuscation & VMs** | Control Flow Flattening (OLLVM), Opaque Predicates, VMProtect/Themida | `references/obfuscation-and-virtual-machines.md` |
| **Memory / RAM** | Dynamic snapshot diffing, pointer chains, Frida memory hooks | `references/dynamic-memory-diffing.md` |
| **Symbolic & Emulation**| Unicorn Engine, Qiling Framework, angr path exploration, Z3 solver | `references/symbolic-and-emulation.md` |
| **Consensus Decompilation**| Reconciling Ghidra, IDA Pro, Binary Ninja, and ILSpy outputs | `references/decompilation-consensus.md` |
| **Code Reconstruction** | Transforming pseudocode into compilable C# (.NET 8), C++20, Python | `references/pseudocode-to-raw-code.md` |
| **Verification Loop** | Differential test benches, 1,000 synthetic vectors, 100% equivalence | `references/verification-loop.md` |

---

## 4. Coding Standards for Output Deliverables

When generating reverse-engineered code for the user:
1. **Compilable by Default:** Never leave unresolved pseudo-variables like `v1` or `a1` in final deliverables. Reconstruct explicit types and meaningful names.
2. **C# Best Practices:** Target .NET 8 idioms. Use `Span<T>`, `ReadOnlySpan<T>`, `[StructLayout(LayoutKind.Explicit)]`, `[FieldOffset(0x...)]`, and pattern matching.
3. **C++ Best Practices:** Target modern C++20. Use `std::span`, fixed-width types (`uint32_t`, `int64_t`), and avoid raw pointer arithmetic where references or spans fit.
4. **Zero-Hallucination Proof:** If an algorithm was reconstructed from disassembly, state the exact verification method used (e.g. Unicorn emulation test vectors or symbol table match).
