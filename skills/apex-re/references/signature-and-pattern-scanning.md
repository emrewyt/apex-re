# Signature & Pattern Scanning Guide
## Autonomous Offset Resolution & Pattern Generation

Fixed memory offsets and function addresses break on every executable patch, recompilation, or update. Reverse engineers and automated agents rely on **Signature / Pattern Scanning** to dynamically locate target functions, structures, and global singletons at runtime.

---

## 1. IDA / Cheat Engine Wildcard Pattern Syntax

A signature consists of a hexadecimal byte sequence interleaved with single-byte wildcards (`?` or `??`):

```text
48 8B 05 ? ? ? ? 48 85 C0 74 ? 48 8B 48 20
```

- Concrete hex pairs match exact instruction opcodes.
- `?` or `??` match any byte (typically dynamic displacements, relative branch offsets, or immediate values).

### Using `sig_scan.py` to Find Patterns

```bash
# Basic wildcard scan
python skills/apex-re/scripts/sig_scan.py scan TargetBinary.exe "48 8B 05 ? ? ? ? 48 85 C0"

# Scan with automatic x86_64 RIP-relative resolution
python skills/apex-re/scripts/sig_scan.py scan GameAssembly.dll "48 8B 05 ? ? ? ? 48 85 C0" --rip 3 7 --base 0x140000000
```

---

## 2. x86_64 RIP-Relative Displacement Mathematics

In 64-bit x86 architecture, memory operands relative to the instruction pointer (`RIP`) use a signed 32-bit displacement relative to the **next instruction**:

```text
Offset 0x1000:  48 8B 05 45 23 01 00    mov rax, [rip + 0x12345]
Offset 0x1007:  48 85 C0                test rax, rax
```

### Exact Calculation Formula
$$\text{Next RIP} = \text{MatchOffset} + \text{InstructionLength}$$
$$\text{Target RVA} = \text{Next RIP} + \text{int32}(\text{Displacement})$$
$$\text{Target VA} = \text{ImageBase} + \text{Target RVA}$$

In `sig_scan.py`:
- `disp_offset_within_match = 3` (starts at byte index 3 of the instruction)
- `instruction_length = 7`
- Displacement is read as a signed 32-bit little-endian integer (`<i`).

---

## 3. Autonomous Signature Synthesis

To generate a stable, minimal signature for a target function or address:

```bash
python skills/apex-re/scripts/sig_scan.py synth TargetBinary.exe 0x140234A10 --max-len 48
```

The tool:
1. Progressively reads instructions from the target address.
2. Automatically replaces RIP-relative displacements (e.g. `48 8B 05 ?? ?? ?? ??`) and relative calls (`E8 ?? ?? ?? ??`) with wildcards.
3. Tests uniqueness against the entire binary.
4. Outputs ready-to-use C++ `#define` macros and C# `.NET 8` constants.
