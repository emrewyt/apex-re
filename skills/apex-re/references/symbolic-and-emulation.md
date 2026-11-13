# Symbolic Execution, SMT Solvers & Emulation Frameworks

Technical guide for applying symbolic execution, CPU emulation (Unicorn Engine, Qiling), and SMT constraint solving (Z3, angr) to reverse engineer proprietary algorithms and solve mathematical protections.

---

## 1. Tool Selection Matrix

| Engine | Layer | Strengths | Ideal Scenario |
| :--- | :--- | :--- | :--- |
| **Unicorn Engine** | Raw CPU Emulation | Extreme speed, multi-architecture (x86, x64, ARM64), byte-level control. | Isolated cryptographic routines, hashing loops, VM dispatcher execution. |
| **Qiling Framework** | OS + CPU Emulation | Emulates Windows APIs, Linux syscalls, PE/ELF loaders, memory pages. | Running complex binaries without running the actual operating system or host environment. |
| **angr** | Symbolic Execution | AST constraint extraction, state exploration, automated path solving. | Reaching specific code targets, solving branch constraints, finding inputs. |
| **Z3 Prover** | SMT Constraint Solver | High-performance mathematical theorem proving and bitvector constraint solving. | Solving opaque constants, license equations, and crypto key inverses. |

---

## 2. Emulating Binary Slices with Unicorn Engine

When an isolated function is heavily obfuscated or contains anti-debugging logic, execute it in a clean Unicorn sandbox:

```python
from unicorn import *
from unicorn.x86_const import *

# Initialize 64-bit x86 emulator
mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map 2MB of memory for code and stack
BASE_ADDR = 0x140000000
STACK_ADDR = 0x7FFF0000
mu.mem_map(BASE_ADDR, 2 * 1024 * 1024)
mu.mem_map(STACK_ADDR, 1024 * 1024)

# Write target machine code into emulator memory
CODE = bytes.fromhex("4889E54883EC20897DFC8B45FC83C0054889EC5DC3") # func: return arg + 5
mu.mem_write(BASE_ADDR, CODE)

# Setup registers
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + 0x80000)
mu.reg_write(UC_X86_REG_RDI, 42) # First argument in System V ABI

# Emulate execution
mu.emu_start(BASE_ADDR, BASE_ADDR + len(CODE))

# Retrieve result
result = mu.reg_read(UC_X86_REG_RAX)
print(f"[+] Emulation Complete. Return Value (RAX): {result}")
```

---

## 3. Symbolic Path Exploration with angr

Use angr to explore paths through complex branching logic and automatically calculate the input that triggers a target block:

```python
import angr
import claripy

# Load binary with angr
project = angr.Project("target_binary.exe", auto_load_libs=False)

# Create 32-byte symbolic bitvector for user input
sym_input = claripy.BVS("sym_input", 32 * 8)

# Initialize simulation state with symbolic input
state = project.factory.full_init_state(args=["target_binary.exe", sym_input])
simgr = project.factory.simulation_manager(state)

# Define target addresses
TARGET_ADDR = 0x140002A50 # "Access Granted" basic block
AVOID_ADDR  = 0x140002A90 # "Access Denied" basic block

# Explore paths
simgr.explore(find=TARGET_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    solution_state = simgr.found[0]
    solved_bytes = solution_state.solver.eval(sym_input, cast_to=bytes)
    print(f"[+] Reached Target Block! Input: {solved_bytes}")
```

---

## 4. Solving Algorithmic Constraints with Z3

When decompiled pseudocode contains bitwise transformation loops (e.g. hash verification, custom decryption keys), translate the operations directly into Z3:

```python
from z3 import *

solver = Solver()

# Define symbolic 32-bit input variables
k0 = BitVec('k0', 32)
k1 = BitVec('k1', 32)

# Decompiled mathematical constraints:
# (k0 ^ 0x5A5A5A5A) + (k1 << 3) == 0xDEADBEEF
# (k1 ^ 0x3C3C3C3C) - (k0 >> 2) == 0xCAFEBABE
solver.add((k0 ^ 0x5A5A5A5A) + (k1 << 3) == 0xDEADBEEF)
solver.add((k1 ^ 0x3C3C3C3C) - LShR(k0, 2) == 0xCAFEBABE)

if solver.check() == sat:
    model = solver.model()
    print(f"[+] Key 0 : 0x{model[k0].as_long():08X}")
    print(f"[+] Key 1 : 0x{model[k1].as_long():08X}")
```
