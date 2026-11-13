# .NET Reverse Engineering: Framework, Modern .NET (.NET 5-10) & NativeAOT

Comprehensive technical reference for deconstructing managed .NET binaries, single-file bundles, ReadyToRun images, and NativeAOT ahead-of-time compiled binaries.

---

## 1. Managed .NET Ecosystem Overview

```text
Target Binary
├── .NET Framework (3.5 - 4.8.1)  -> Pure IL, mscoree.dll, full ECMA-335 metadata
├── .NET Core / 5 - 10            -> CoreCLR, hostfxr.dll, ReadyToRun (R2R)
├── Single-File Executable        -> AppHost wrapper containing embedded DLLs
└── .NET NativeAOT (8 / 9 / 10)   -> Fully compiled native x64/ARM64 machine code, no CLR JIT
```

---

## 2. Decompiling Standard Managed Binaries (.NET 3.5 to 10)

### 2.1 IL Decompilation Engine
For standard managed assemblies containing ECMA-335 metadata:
- **Primary CLI Tool:** `ilspycmd`
  ```bash
  ilspycmd -p -o ./decompiled_solution TargetAssembly.dll
  ```
- **GUI Analyzers:** dnSpy (dynamic debugging and patching) and ILSpy (clean modern C# syntax synthesis).

### 2.2 Unpacking Single-File Applications
Modern .NET allows publishing as a single `.exe` file (`PublishSingleFile=true`).
- **Structure:** Native AppHost launcher followed by a bundle bundle header with embedded DLLs and PDBs.
- **Extraction:**
  Use `bundle-extract` or Python:
  ```bash
  bundle-extract -i TargetSingleFile.exe -o ./extracted_assemblies/
  ```
  Once extracted, the main game/application assembly (e.g. `App.dll`) can be opened directly in ILSpy.

---

## 3. ReadyToRun (R2R) Images

ReadyToRun compiles IL methods into native code ahead of time while preserving the original IL bytecode for cross-platform fallback.
- **Format:** PE file with a CLI Header (`IMAGE_COR20_HEADER`). The `Flags` field contains `COMIMAGE_FLAGS_IL_LIBRARY` (`0x00000004`) or `0x10`.
- **Analysis:**
  If an obfuscator wiped the IL bytecode but kept the R2R native instructions, standard decompilers fail.
  - Use `R2RDump` from the .NET SDK:
    ```bash
    R2RDump.exe --in TargetAssembly.dll --out r2r_disasm.txt --all
    ```
  - This disassembles the exact native x64/ARM64 machine instructions executed by the CLR.

---

## 4. .NET NativeAOT Deep Dive (.NET 7, 8, 9, 10)

In NativeAOT mode (`PublishAot=true`), the C# compiler generates direct machine code using LLVM/RyuJIT. No virtual machine or JIT runtime exists.

### 4.1 Fingerprinting NativeAOT
- **Entry Point:** Calls `__managed__Main` through native runtime startup.
- **Runtime Exports:** Links statically with `bootstrapper.obj` and `Runtime.WorkstationGC.lib`.
- **String Table:** All strings are stored as standard UTF-16 little-endian literals in the `.rdata` section.
- **Key Internal Symbols:**
  - `RhpCreateTypeMesh`
  - `RhpReversePInvoke2`
  - `RhpAssignRef` (Garbage collection write barrier)
  - `RhpNewFast` / `RhpNewArray` (Memory allocation)

### 4.2 Reconstructing Types and VTables
1. **Method Tables (`EEType`):**
   In NativeAOT, each type is represented by an `EEType` struct in `.rdata`:
   ```cpp
   struct EEType {
       uint16_t ComponentSize; // Array element size or 0
       uint16_t Flags;         // ValueType, Interface, Finalizable
       uint32_t BaseSize;      // Instance size in memory
       EEType*  RelatedType;   // Base class or element type
       void*    InterfaceMap;  // Implemented interfaces
       void*    VTable[1];     // Virtual method pointers
   };
   ```
2. **Recovering Calls:**
   - Inlined calls can be identified by the GC write barrier `call RhpAssignRef`.
   - String literals directly point to `String` objects with a 4-byte length prefix followed by UTF-16 characters.

---

## 5. De-obfuscation Strategies

| Obfuscator | Characteristics | Apex-RE De-obfuscation Technique |
| :--- | :--- | :--- |
| **ConfuserEx** | Control flow mangling, string encryption, anti-dump | Run `de4dot -p unconfuser` or use memory dumper at runtime |
| **Agile.NET** | Virtualized methods, encrypted resources | Hook `Assembly.Load` in dnSpy debugger to capture raw assemblies |
| **Eazfuscator** | String encryption, dynamic proxy calls | Run `de4dot -p ef` to decrypt strings and inline proxies |
| **Costura.Fody** | Assemblies compressed in resources | Extract zip stream from resource `"costura.*"` |
