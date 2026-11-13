# Godot Engine Reverse Engineering Guide

Comprehensive guide for inspecting, unpacking, decompiling, and modifying Godot Engine 3.x and 4.x games.

---

## 1. Packaging Architecture: The `.pck` Format

Godot packages resources, scenes, scripts, and assets into `.pck` files or embeds them directly at the end of the game executable.

### 1.1 Header and Directory Structure

A standalone `.pck` begins with the 4-byte ASCII magic:
```text
0x00 - 0x03 : Magic "GDPC" (0x43504447)
0x04 - 0x07 : Package format version (e.g. 1 or 2)
0x08 - 0x0B : Godot engine major version (3 or 4)
0x0C - 0x0F : Godot engine minor version
0x10 - 0x13 : Godot engine patch version
0x14 - 0x17 : Flags (Bit 0: Encrypted directory)
0x18 - 0x27 : Reserved padding (16 bytes in v2)
0x28 - 0x2B : File count (N)
```

Following the file count, directory entries are stored sequentially:
```text
For each file in N:
  - Path length (4 bytes uint32)
  - Path string (UTF-8 bytes, length-padded)
  - Offset in package (8 bytes uint64)
  - Size on disk (8 bytes uint64)
  - MD5 hash / Flags (16 bytes)
```

### 1.2 Embedded PCK in Executables
When no external `.pck` exists, Godot appends the package to the executable binary. The engine checks the last 12 bytes of the executable:
- Magic: `0x43504447` (`GDPC`)
- Package offset from end: 8-byte uint64.

---

## 2. GDScript Bytecode & Decompilation

Godot compiles `.gd` source files into binary `.gdc` bytecode files.

### 2.1 Bytecode Format
```text
0x00 - 0x03 : Magic "GDSC" (Godot Script Compiled)
0x04 - 0x07 : Bytecode format version
0x08 - 0x0B : Token count / Identifier count
... Constants Table (Variant serialization)
... Bytecode Opcode Stream
```

### 2.2 Tooling and Decompilation
- **GDRE Tools (Godot Reverse Engineering Tools):**
  Full recovery tool for Godot 2.x, 3.x, and 4.x:
  ```bash
  gdre_tools --headless --recover="Game.pck" --output-dir="recovered_project/"
  ```
  Recovers project files, scenes (`.tscn`), resources (`.tres`), scripts (`.gd`), and reconstructs `project.godot`.

### 2.3 Handling Encrypted PCK Files
If a developer encrypted the project with an AES-256 key:
1. Extract the key from the game executable. The key is compiled into the binary as an array of 32 bytes (`script_encryption_key`).
2. Search for the string `"godot_crypto"` or the call to `CryptoCore::aes_decrypt_cbc`.
3. Locate the 32-byte hexadecimal AES key in `.rdata` and feed it into GDRE Tools:
   ```bash
   gdre_tools --recover="Game.pck" --key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
   ```

---

## 3. GDExtension (Godot 4) & GDNative (Godot 3)

Modern high-performance Godot games write intensive logic in C++ via GDExtension libraries (`.dll` / `.so` / `.dylib`).

### 3.1 Resolving GDExtension Entry Point
Every GDExtension binary exports an initialization function:
```c
GDExtensionBool GDExtensionInit(
    GDExtensionInterfaceGetProcAddress p_get_proc_address,
    GDExtensionClassLibraryPtr p_library,
    GDExtensionInitialization *r_initialization
);
```
- By analyzing `GDExtensionInit`, you can enumerate all registered C++ classes, exported methods, property getters/setters, and signals passed into Godot's ClassDB.

### 3.2 In-Memory Object Hierarchy
All Godot objects inherit from `Object` -> `Node` -> `Node2D` / `Node3D`.
- To inspect game hierarchy in memory:
  - Find `SceneTree::singleton` in memory.
  - Traverse `root` -> `get_children()` to enumerate active nodes, player states, and logic scripts.
