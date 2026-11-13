# Game Engine Reverse Engineering: Unreal Engine 4/5 & Unity (Mono / IL2CPP)

Technical reference guide for autonomous reverse engineering of Unreal Engine 4, Unreal Engine 5, Unity Mono, and Unity IL2CPP game binaries.

---

## 1. Unreal Engine 4 and 5 Internals

### 1.1 Core Reflection Data Structures

Unreal Engine relies on a centralized reflection system. All game objects inherit from `UObject` and are indexed in global reflection arrays.

```text
Global Root
├── GNames / FNamePool      -> String table storing names of classes, properties, functions
├── GUObjectArray           -> Global index of all allocated UObject instances
└── GWorld / UWorld         -> The active game world (Levels, Actors, GameState, LocalPlayers)
```

#### FNamePool Layout (UE 4.23 to UE 5.x)
In modern Unreal versions, `FNamePool` replaces the legacy chunked pointer array:
- Names are stored in blocks of 64KB (`FNameEntryAllocator`).
- Each entry is preceded by an `FNameEntryHeader` (2 bytes):
  - Bit 0: Wide string flag (1 = UTF-16, 0 = Ansi).
  - Bits 1..5: Lowercase probe hash.
  - Bits 6..15: String length (up to 1024 characters).
- Address calculation:
  ```cpp
  uint32_t BlockIndex = FNameIndex >> 16;
  uint16_t BlockOffset = FNameIndex & 0xFFFF;
  uintptr_t EntryAddress = Blocks[BlockIndex] + (BlockOffset * sizeof(FNameEntryHeader));
  ```

#### GUObjectArray Layout
`GUObjectArray` holds an array of `FUObjectItem`:
```cpp
struct FUObjectItem {
    UObject* Object;
    int32_t Flags;
    int32_t ClusterRootIndex;
    int32_t SerialNumber;
};
```
- In UE4/UE5 shipping builds, `Objects` is chunked: 65,536 objects per chunk (`FUObjectItem** Objects`).
- Resolving Object by ID:
  ```cpp
  int32_t ChunkIndex = Index / 65536;
  int32_t WithinChunk = Index % 65536;
  FUObjectItem* Item = &ChunkTable[ChunkIndex][WithinChunk];
  UObject* Target = Item->Object;
  ```

### 1.2 Resolving GWorld and Player Controllers

To find the game local player and entities:
```text
GWorld (UWorld*)
  └── OwningGameInstance (UGameInstance*)
        └── LocalPlayers (TArray<ULocalPlayer*>)
              └── [0] PlayerController (APlayerController*)
                    ├── AcknowledgedPawn (APawn*)
                    └── PlayerCameraManager (APlayerCameraManager*)
```

### 1.3 Signature Scanning Heuristics for Unreal

1. **GNames / FNamePool Signature:**
   Look for the initialization string `"ByteProperty"`, `"IntProperty"`, `"FloatProperty"` or references to `FName::Init()`.
2. **ProcessEvent Hooking:**
   `UObject::ProcessEvent` is the universal function dispatcher for all Blueprints and RPCs:
   ```cpp
   void ProcessEvent(UObject* Context, UFunction* Function, void* Parms);
   ```
   Hooking `ProcessEvent` provides a complete execution log of every script call, UI interaction, and network RPC with zero symbols needed.

---

## 2. Unity: Mono vs IL2CPP Deconstruction

### 2.1 Unity Mono Architecture
- **Assemblies Location:** `YourGame_Data/Managed/`
- **Core Files:** `Assembly-CSharp.dll`, `UnityEngine.dll`, `UnityEngine.CoreModule.dll`
- **Triage:** Open `Assembly-CSharp.dll` directly in ILSpy or dnSpy.
- **De-obfuscation:** If names are encrypted or methods stripped, run `de4dot` to clean control flow and restore token tables.

### 2.2 Unity IL2CPP Architecture
IL2CPP compiles C# Intermediate Language (IL) ahead-of-time into native C++ code, which is then compiled into a native binary (`GameAssembly.dll` on Windows, `libil2cpp.so` on Android/Linux, Mach-O binary on iOS/macOS).

#### Metadata Pairing
- `GameAssembly.dll`: Contains compiled native machine instructions (functions, vtables, thunks).
- `global-metadata.dat`: Located in `YourGame_Data/il2cpp_data/Metadata/global-metadata.dat`.
  - Header magic: `0xFAB11BAF` (Sanity magic: 29 in decimal for IL2CPP v29).
  - Contains all type definitions, field names, method signatures, strings, and attribute tables.

#### Automated Solution Reconstruction Workflow
1. Run `Il2CppDumper`:
   ```bash
   Il2CppDumper.exe GameAssembly.dll global-metadata.dat ./dump_output
   ```
   Generates `dump.cs` (pure C# signatures), `script.json`, and IDA/Ghidra symbol renaming python scripts.
2. Run `Cpp2IL`:
   ```bash
   Cpp2IL.exe --game-path "C:/Games/TargetUnityGame" --analysis-level 4 --output-as deobfuscated-csharp
   ```
   Reconstructs a fully browsable, decompiled C# Visual Studio solution (`.sln`) with method bodies restored from native assembly instructions.

### 2.3 Runtime Memory Manipulation via IL2CPP API

Injected DLLs or Frida scripts can invoke IL2CPP exports directly without reverse engineering individual compiler thunks:
```c
// Resolve il2cpp domain and assemblies
Il2CppDomain* domain = il2cpp_domain_get();
const Il2CppAssembly* assembly = il2cpp_domain_assembly_open(domain, "Assembly-CSharp");
const Il2CppImage* image = il2cpp_assembly_get_image(assembly);

// Lookup class and method
Il2CppClass* playerKlass = il2cpp_class_from_name(image, "GameNamespace", "PlayerController");
MethodInfo* setHpMethod = il2cpp_class_get_method_from_name(playerKlass, "SetHealth", 1);

// Call method dynamically
void* params[1] = { &newHealth };
il2cpp_runtime_invoke(setHpMethod, playerInstance, params, NULL);
```
