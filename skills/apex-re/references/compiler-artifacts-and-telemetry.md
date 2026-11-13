# Compiler Artifacts & Telemetry Guide
## MSVC Rich Header, Demangling & Toolchain Fingerprinting

Binaries carry subtle compilation artifacts left by linkers, optimizers, and runtime libraries. These artifacts allow an agent to pinpoint the exact compiler version, optimization level, and source language.

---

## 1. MSVC Rich Header Decoding

The MSVC Rich Header is an undocumented data structure located between the DOS header (`0x40`) and the PE header. It records every compiler tool, language frontend, and linker invocation used during the build.

### Header Structure
```text
[DOS Header: 0x00 .. 0x3F]
[DOS Stub / Rich Block]
   ├── "DanS" ^ Key (0x536E6144 ^ XOR_KEY)
   ├── 3x Padding DWORDs (0 ^ XOR_KEY)
   ├── Entry Records (8 bytes each):
   │     ├── CompID DWORD: (ProductID << 16) | BuildID
   │     └── Count DWORD: Number of object files linked
   └── "Rich" Marker (0x68636952) + XOR_KEY DWORD
[PE Signature: 'PE\0\0']
```

### Common MSVC Product IDs
| Product ID | Tool Name | Compiler Suite |
| :--- | :--- | :--- |
| `0x00FF` | C++ Compiler (Utc1900) | Visual Studio 2015 |
| `0x0103` | C++ Compiler (Utc1910) | Visual Studio 2017 |
| `0x0104` | C++ Compiler (Utc1920 / Utc1930) | Visual Studio 2019 / 2022 |
| `0x0105` | Linker (Linker1430) | Visual Studio 2019 / 2022 |
| `0x0107` | MASM Assembler | Visual Studio 2019 / 2022 |

Apex-RE automatically extracts this telemetry:
```bash
python skills/apex-re/scripts/apex_triage.py TargetApp.exe --json
```

---

## 2. Universal Symbol Demangling

Compilers encode function namespaces, parameter types, and calling conventions into symbol names:

### MSVC C++ (`?` Prefix)
- Example: `?CalculateDamage@PlayerEntity@@QEAAHHM@Z`
  - `?`: MSVC mangling prefix
  - `CalculateDamage`: Method name
  - `@PlayerEntity@@`: Class name
  - `QEAA`: Public member function, non-static, x64 `__fastcall`
  - `H`: Return type `int`
  - `HM`: Parameters `int, float`

### Itanium / GCC / Clang (`_Z` Prefix)
- Example: `_ZN12PlayerEntity15CalculateDamageEif`
  - `_Z`: Itanium prefix
  - `N`: Nested name (class scope)
  - `12PlayerEntity`: Class name (length 12)
  - `15CalculateDamage`: Method name (length 15)
  - `E`: End of nested scope
  - `i`: Parameter `int`
  - `f`: Parameter `float`

### Rust (`_ZN` or `$CRATE$` Prefix)
- Example: `_ZN6player12PlayerEntity15calculate_damage17h1234567890abcdefE`
  - Demangled: `player::PlayerEntity::calculate_damage::h1234567890abcdef`
