# MSVC, CMake & Native C/C++ Binary Reverse Engineering

Technical guide for reverse engineering native C/C++ executables and libraries compiled with Microsoft Visual C++ (MSVC), GCC, Clang, and modern CMake toolchains.

---

## 1. Calling Conventions & Register State

### 1.1 x64 Architecture Conventions

| Parameter Order | Windows x64 (MSVC / Fastcall) | System V AMD64 (Linux / macOS / GCC) |
| :--- | :--- | :--- |
| **Param 1** | `RCX` (or `XMM0` for float) | `RDI` (or `XMM0` for float) |
| **Param 2** | `RDX` (or `XMM1` for float) | `RSI` (or `XMM1` for float) |
| **Param 3** | `R8` (or `XMM2` for float) | `RDX` (or `XMM2` for float) |
| **Param 4** | `R9` (or `XMM3` for float) | `RCX` (or `XMM3` for float) |
| **Param 5+** | Stack (right to left, shadow space allocated) | `R8`, `R9`, then Stack |
| **Return** | `RAX` (or `XMM0` for float) | `RAX` (or `XMM0` for float) |
| **Shadow Space** | 32 bytes allocated by caller (`RSP + 0x20`) | None (128-byte Red Zone below `RSP`) |

---

## 2. MSVC C++ RTTI & VTable Reconstruction

When MSVC compiles C++ code with Run-Time Type Information (`/GR`), virtual method tables (`vftable`) contain full class names and inheritance hierarchies in `.rdata`.

```text
Memory Layout at VTable Address
[Address - 8] -> RTTICompleteObjectLocator*
[Address + 0] -> VirtualMethod_0*
[Address + 8] -> VirtualMethod_1*
...
```

### 2.1 CompleteObjectLocator Struct
```cpp
struct RTTICompleteObjectLocator {
    uint32_t signature;           // 0 on 32-bit, 1 on 64-bit (relative offsets)
    uint32_t offset;              // Offset of this vtable in the complete class
    uint32_t cdOffset;            // Constructor displacement offset
    int32_t  pTypeDescriptor;     // Relative virtual address (RVA) to TypeDescriptor
    int32_t  pClassHierarchy;     // RVA to RTTIClassHierarchyDescriptor
    int32_t  pSelf;               // RVA to this CompleteObjectLocator
};
```

### 2.2 TypeDescriptor Struct
```cpp
struct TypeDescriptor {
    void*   pVFTable;            // &type_info::`vftable'
    void*   spare;               // NULL
    char    name[1];             // Mangled class name (e.g. ".?AVPlayerCharacter@@")
};
```

### 2.3 Automated Recovery Algorithm
1. Locate all `.?AV` ASCII strings in `.rdata`.
2. Find cross-references pointing to the string's start address minus 16 (the start of `TypeDescriptor`).
3. Scan `.rdata` for `RTTICompleteObjectLocator` structures that reference this `TypeDescriptor` RVA.
4. Scan `.rdata` for pointers pointing to `RTTICompleteObjectLocator` + 1 pointer size (this marks the start of the virtual function table `vftable`).
5. Every consecutive function pointer in that table belongs to that class.

---

## 3. Demangling C++ Symbols

### 3.1 MSVC Decorator Rules
- Format: Starts with `?`
- Methods: `?MethodName@ClassName@@AccessSpecifierSignature`
- Demangling with CLI:
  ```cmd
  undname.exe "?TakeDamage@Player@@QEAAHXZ"
  # Output: public: int __cdecl Player::TakeDamage(void)
  ```

### 3.2 GCC / Clang Itanium ABI Decorator Rules
- Format: Starts with `_Z`
- Demangling with CLI:
  ```bash
  c++filt _ZN6Player10TakeDamageEv
  # Output: Player::TakeDamage()
  ```

---

## 4. Standard Library Internal Memory Layouts (MSVC STL)

Recognizing standard library types in memory is vital when analyzing decompiled structs:

### `std::vector<T>` (24 bytes on x64)
```cpp
struct std_vector {
    T* _Myfirst; // Pointer to beginning of elements
    T* _Mylast;  // Pointer to current end of elements (size = _Mylast - _Myfirst)
    T* _Myend;   // Pointer to allocated capacity end (capacity = _Myend - _Myfirst)
};
```

### `std::string` (32 bytes on x64 with Small String Optimization - SSO)
```cpp
struct std_string {
    union {
        char _Buf[16]; // Inline buffer used if string length < 16
        char* _Ptr;    // Allocated heap buffer if length >= 16
    } _Bx;
    size_t _Mysize;    // String character length
    size_t _Myres;     // Buffer capacity
};
```
