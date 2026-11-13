# Python Binary & Bytecode Reverse Engineering

Technical guide for extracting, repairing, decompiling, and de-obfuscating Python executables (PyInstaller, cx_Freeze, py2exe) and compiled bytecode (`.pyc`).

---

## 1. Python Executable Bundles (PyInstaller)

PyInstaller packages the Python interpreter, dependencies, and compiled bytecode into a single executable.

```text
PyInstaller Executable (PE / ELF)
├── Bootstrapper Code            -> Extracts files to temp folder or runs in-memory
├── Python Runtime DLL           -> python3X.dll embedded
└── Archive Overlay (CArchive)   -> Contains table of contents, Zlib streams of .pyc files
```

### 1.1 Unpacking with `pyinstxtractor`
To extract all embedded modules and assets:
```bash
python pyinstxtractor.py target_application.exe
```
This produces an extraction folder containing:
- `struct.pyc`
- `target_application.pyc` (or entry point script)
- Decrypted standard library `.pyc` modules.

### 1.2 Fixing Missing `.pyc` Headers
`pyinstxtractor` extracts raw bytecode without the 16-byte `.pyc` header for the main script. To repair it for decompiler compatibility:
1. Open `struct.pyc` (which has a valid header) in a hex editor.
2. Copy the first 16 bytes:
   - Bytes 0..3: Python magic number (determines Python version).
   - Bytes 4..7: Bit field flags (PEP 552: 0 = timestamp-based, 1 = hash-based).
   - Bytes 8..15: Timestamp and file size, or siphash.
3. Prepend these 16 bytes to the extracted entry script before decompilation.

#### Python Magic Number Reference Table
| Python Version | Magic Number (Hex Little-Endian) |
| :--- | :--- |
| **Python 3.8** | `55 0D 0D 0A` |
| **Python 3.9** | `61 0D 0D 0A` |
| **Python 3.10** | `6F 0D 0D 0A` |
| **Python 3.11** | `A7 0D 0D 0A` |
| **Python 3.12** | `CB 0D 0D 0A` |
| **Python 3.13** | `EE 0D 0D 0A` |

---

## 2. Decompiling `.pyc` Bytecode

### 2.1 Tool Selection
- **`pycdc` (Decompyle++):** Written in C++, supports Python 3.8 through 3.13:
  ```bash
  pycdc target_script.pyc > recovered_source.py
  ```
  If instructions cannot be cleanly decompiled, it emits `/* WARNING: Decompyle failed */` alongside Python disassembly.
- **Python Standard Library `dis` Module:**
  When full source reconstruction fails, inspect the raw bytecode opcodes:
  ```python
  import dis, marshal
  with open("target_script.pyc", "rb") as f:
      f.seek(16) # Skip header
      code_obj = marshal.load(f)
      dis.dis(code_obj)
  ```

---

## 3. De-obfuscating PyArmor & Virtualized Python

PyArmor encrypts Python code objects and decrypts them in memory on demand through a native C extension (`pytransform.dll` / `_pytransform.so`).

### 3.1 Architecture of PyArmor
- Replaces function bytecode (`co_code`) with a stub that calls PyArmor's runtime.
- The runtime hooks Python's internal frame evaluation function `PyEval_EvalFrameDefault`.

### 3.2 Dynamic Dumping via Frida
Because the native runtime must pass decrypted bytecode to the Python interpreter before execution, hook `PyEval_EvalFrameDefault` to dump clean code objects:

```javascript
// Frida script: dump_pyarmor.js
Interceptor.attach(Module.findExportByName("python311.dll", "PyEval_EvalFrameDefault"), {
    onEnter: function(args) {
        var frame = args[0]; // PyFrameObject*
        // Resolve frame->f_code (PyCodeObject*)
        var f_code = frame.add(24).readPointer();
        var co_name = f_code.add(80).readPointer(); // String object
        console.log("[PyArmor Hook] Executing function: " + co_name);
        // Dump co_code buffer here before cipher re-locks it
    }
});
```
