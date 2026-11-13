# Contributing to Apex-RE

We welcome contributions from reverse engineers, compiler enthusiasts, and AI agent developers.

---

## Development Guidelines

1. **Zero External Dependencies:**
   All core scripts in `skills/apex-re/scripts/` must run on Python 3 standard library without requiring `pip install`.
2. **Deterministic & Cross-Platform:**
   Code must run identically across Windows, Linux, and macOS.
3. **Comprehensive Testing:**
   Any new parser, unpacker, or analysis utility must include unit tests in `tests/test_apex_scripts.py`. Run tests locally before opening a pull request:
   ```bash
   python -m unittest discover -s tests -p "test_*.py" -v
   ```
4. **Documentation Quality:**
   All documentation must follow the aesthetic standards of Apex-RE:
   - Use clean SVG icons and badges (no emojis).
   - Maintain clear Mermaid architecture diagrams.
   - Provide concrete, verified code snippets in C# (.NET 8), modern C++20, and Python.

---

## Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Ensure all tests pass with zero failures.
3. Open a pull request describing the technical challenge, the methodology used, and test outputs.
