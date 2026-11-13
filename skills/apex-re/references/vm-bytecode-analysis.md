# Virtual Machine & Bytecode Analysis Guide
## Deconstructing Interpreted & Virtualized Execution Loops

Software protected by code virtualization (VMProtect, Themida, Code Virtualizer, or custom proprietary bytecode engines) converts native assembly into pseudo-bytecode executed by an internal software interpreter.

---

## 1. Architecture of a Virtual Machine Loop

A virtualization interpreter revolves around four architectural components:
1. **VIP (Virtual Instruction Pointer):** Dedicated register (e.g. `rsi` or `r14`) pointing to encrypted bytecode.
2. **VSP (Virtual Stack Pointer):** Dedicated register (e.g. `rbp` or `r15`) pointing to the virtual evaluation stack.
3. **VM Context:** A heap or stack structure holding mapped native CPU registers (RAX, RBX, RCX, RDX...).
4. **Dispatcher Loop:**
   ```nasm
   loc_dispatcher:
       movzx   eax, byte ptr [rsi]     ; Fetch virtual opcode
       inc     rsi                     ; Advance VIP
       jmp     qword ptr [r12 + rax*8] ; Jump to handler via jump table
   ```

---

## 2. Devirtualization Pipeline with `vm_analyzer.py`

Tracing a virtualized loop naively yields hundreds of thousands of identical dispatcher instructions. The Apex-RE devirtualization pipeline removes this noise:

```text
[Raw Execution Trace]
         │
         ▼
[Frequency Analysis] ──> Identifies Dispatcher Addresses (executed 100x more than handlers)
         │
         ▼
[Overhead Filtering] ──> Strips VIP incrementation and dispatcher jumps
         │
         ▼
[Handler Classification] ──> Labels operations (VPUSH, VPOP, VALU_ADD, VALU_XOR, VMOV)
         │
         ▼
[Backward Symbolic Slicing] ──> Isolates dependencies for target register (e.g. RAX at exit)
         │
         ▼
[Compilable Formula / C Code]
```

### Running the Analyzer

```bash
# Analyze trace and perform backward slice on RAX
python skills/apex-re/scripts/vm_analyzer.py execution_trace.log --slice rax
```

---

## 3. Handler Pattern Signatures

| Semantic Operation | Common Handler Implementation |
| :--- | :--- |
| **`VPUSH Reg`** | `mov rax, [vm_ctx + off]; sub vsp, 8; mov [vsp], rax; jmp dispatcher` |
| **`VPUSH Imm`** | `mov rax, [vip]; add vip, 8; sub vsp, 8; mov [vsp], rax; jmp dispatcher` |
| **`VPOP Reg`** | `mov rax, [vsp]; add vsp, 8; mov [vm_ctx + off], rax; jmp dispatcher` |
| **`VALU ADD`** | `mov rax, [vsp]; add rax, [vsp+8]; add vsp, 8; mov [vsp], rax; jmp dispatcher` |
| **`VALU XOR`** | `mov rax, [vsp]; xor rax, [vsp+8]; add vsp, 8; mov [vsp], rax; jmp dispatcher` |
| **`VBRANCH`** | `test rax, rax; jz loc_false; mov vip, target_true; jmp dispatcher` |

By isolating only the arithmetic and memory writes, the underlying business logic or cryptographic calculation is recovered in clean high-level form.
