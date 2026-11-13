# Apex-RE: Ready-to-Use Agent Prompt Library

Curated system prompt templates and task directives for AI coding agents (Antigravity 2.0, Claude Code, Codex, Cursor) utilizing the **Apex-RE** skill.

---

## Navigation

- [1. Unreal Engine 5 Reflection & Actor Tracing](#1-unreal-engine-5-reflection--actor-tracing)
- [2. Unity IL2CPP Solution Reconstruction](#2-unity-il2cpp-solution-reconstruction)
- [3. .NET 8 NativeAOT Deconstruction](#3-net-8-nativeaot-deconstruction)
- [4. OLLVM Control Flow Unflattening](#4-ollvm-control-flow-unflattening)
- [5. Binary File Format to Kaitai Struct](#5-binary-file-format-to-kaitai-struct)
- [6. Dynamic Memory Snapshot Diffing](#6-dynamic-memory-snapshot-diffing)
- [7. Multi-Engine Consensus Decompilation](#7-multi-engine-consensus-decompilation)
- [8. Round-Trip Equivalence Verification](#8-round-trip-equivalence-verification)
- [9. Wildcard Pattern & RIP-Relative Offset Hunting](#9-wildcard-pattern--rip-relative-offset-hunting)
- [10. VM Devirtualization & Backward Slicing](#10-vm-devirtualization--backward-slicing)

---

## 1. Unreal Engine 5 Reflection & Actor Tracing

### English Prompt
```text
Task: Reverse engineer the entity management system in this Unreal Engine 5 shipping binary.
Target: ShippingGame-Win64-Shipping.exe
Action Plan:
1. Use apex-re triage to locate FNamePool and GUObjectArray offsets.
2. Trace GWorld -> OwningGameInstance -> LocalPlayers[0] -> PlayerController.
3. Consult `references/game-engines-unreal-unity.md` for FNameEntryHeader 7-bit length masks.
4. Hook UObject::ProcessEvent to intercept Blueprint RPC calls without debug symbols.
5. Emit compilable C++20 definitions for the player character and health properties.
```

### Türkçe Prompt
```text
Görev: Bu Unreal Engine 5 shipping binary'sindeki entity yönetim sistemini tersine mühendislikle analiz et.
Hedef: ShippingGame-Win64-Shipping.exe
Eylem Planı:
1. FNamePool ve GUObjectArray ofsetlerini tespit etmek için apex-re triage kullan.
2. GWorld -> OwningGameInstance -> LocalPlayers[0] -> PlayerController zincirini izle.
3. FNameEntryHeader 7-bit uzunluk maskeleri için `references/game-engines-unreal-unity.md` dosyasını incele.
4. Hata ayıklama sembolleri olmadan Blueprint RPC çağrılarını yakalamak için UObject::ProcessEvent fonksiyonunu hook'la.
5. Oyuncu karakteri ve can (health) özellikleri için derlenebilir C++20 tanımlarını üret.
```

---

## 2. Unity IL2CPP Solution Reconstruction

### English Prompt
```text
Task: Reconstruct a complete compilable C# solution from this Unity IL2CPP build.
Inputs: GameAssembly.dll and global-metadata.dat
Action Plan:
1. Run triage to confirm IL2CPP metadata version (Sanity magic 0xFAB11BAF).
2. Execute Il2CppDumper and Cpp2IL using the workflow documented in `references/game-engines-unreal-unity.md`.
3. Resolve method bodies for critical combat and inventory controllers into clean C# 12 / .NET 8 syntax.
4. Eliminate decompiler artifacts and synthesize explicit struct layouts where memory offsets are referenced.
```

### Türkçe Prompt
```text
Görev: Bu Unity IL2CPP derlemesinden eksiksiz, derlenebilir bir C# Visual Studio çözümü üret.
Girdiler: GameAssembly.dll ve global-metadata.dat
Eylem Planı:
1. IL2CPP metadata sürümünü (Sanity magic 0xFAB11BAF) doğrulamak için triage çalıştır.
2. `references/game-engines-unreal-unity.md` içindeki rehbere göre Il2CppDumper ve Cpp2IL adımlarını uygula.
3. Kritik savaş ve envanter sınıflarının fonksiyon gövdelerini temiz C# 12 / .NET 8 sözdizimine dönüştür.
4. Dekompilasyon artılarını temizle ve bellek ofsetlerinin kullanıldığı yerlerde explicit struct tanımları üret.
```

---

## 3. .NET 8 NativeAOT Deconstruction

### English Prompt
```text
Task: Deconstruct a .NET 8 NativeAOT pre-compiled binary.
Target: NativeAOTService.exe
Action Plan:
1. Verify NativeAOT indicators (RhpCreateTypeMesh, RhpReversePInvoke2, System.Private.CoreLib).
2. Follow `references/dotnet-and-nativeaot.md` to locate EEType method tables in .rdata.
3. Reconstruct class hierarchies and virtual function tables.
4. Extract UTF-16 string literals and map internal calls using GC write barriers (RhpAssignRef).
5. Output clean C# interfaces mirroring the internal native implementation.
```

### Türkçe Prompt
```text
Görev: .NET 8 NativeAOT ile derlenmiş yerel ikiliyi tersine mühendislikle deşifre et.
Hedef: NativeAOTService.exe
Eylem Planı:
1. NativeAOT göstergelerini (RhpCreateTypeMesh, RhpReversePInvoke2, System.Private.CoreLib) doğrula.
2. .rdata içindeki EEType method tablolarını bulmak için `references/dotnet-and-nativeaot.md` kılavuzunu izle.
3. Sınıf hiyerarşilerini ve sanal fonksiyon (vtable) tablolarını yeniden inşa et.
4. UTF-16 metin sabitlerini çıkar ve GC write barrier (RhpAssignRef) çağrılarını haritalandır.
5. Dahili mantığı birebir temsil eden temiz C# arayüzleri ve sınıfları üret.
```

---

## 4. OLLVM Control Flow Unflattening

### English Prompt
```text
Task: Deobfuscate an OLLVM Control Flow Flattening (CFF) protected function.
Inputs: Execution trace or basic block transition graph.
Action Plan:
1. Consult `references/obfuscation-and-virtual-machines.md` to isolate the central state dispatcher switch.
2. Run `python scripts/unflatten_trace.py trace.json --format c` to eliminate artificial state variables.
3. Reconstruct native if-else statements and while loops from state transitions.
4. Verify whether any branches contain opaque predicates using Z3 SMT constraints.
```

### Türkçe Prompt
```text
Görev: OLLVM Control Flow Flattening (CFF) korumalı bir fonksiyonu düzleştirilmiş karmaşadan arındır.
Girdiler: Yürütme izi (execution trace) veya temel blok geçiş grafiği.
Eylem Planı:
1. Merkezi durum dağıtıcı (dispatcher switch) bloğunu izole etmek için `references/obfuscation-and-virtual-machines.md` rehberini kullan.
2. Yapay durum değişkenlerini temizlemek için `python scripts/unflatten_trace.py trace.json --format c` komutunu çalıştır.
3. Durum geçişlerinden doğal if-else ve while döngülerini yeniden inşa et.
4. Dallanmalarda opaque predicate olup olmadığını Z3 SMT kısıtları ile matematiksel olarak doğrula.
```

---

## 5. Binary File Format to Kaitai Struct

### English Prompt
```text
Task: Reverse engineer an undocumented proprietary save game / network packet binary format.
Target: savegame.dat
Action Plan:
1. Run `python scripts/kaitai_synth.py savegame.dat --id GameSaveFormat -o game_save.ksy`.
2. Inspect detected magic headers, endianness, string buffers, and primitive fields.
3. Verify the generated YAML specification against multiple sample files to validate array repetitions.
4. Generate corresponding C# (.NET 8) BinaryPrimitives parsing code for fast, allocation-free ingestion.
```

### Türkçe Prompt
```text
Görev: Belgelenmemiş tescilli bir kayıt dosyası / ağ paketi ikili formatını tersine mühendislikle çöz.
Hedef: savegame.dat
Eylem Planı:
1. `python scripts/kaitai_synth.py savegame.dat --id GameSaveFormat -o game_save.ksy` komutunu çalıştır.
2. Tespit edilen sihirli başlıkları (magic), endianness değerini, string tamponlarını ve ilkel alanları incele.
3. Dizi tekrarlarını doğrulamak için üretilen YAML spesifikasyonunu birden fazla örnek dosya üzerinde test et.
4. Sıfır bellek tahsisli hızlı okuma için ilgili C# (.NET 8) BinaryPrimitives ayrıştırma kodunu üret.
```

---

## 6. Dynamic Memory Snapshot Diffing

### English Prompt
```text
Task: Extract entity structure and exact field offsets using memory differential analysis.
Inputs: memory_before.bin and memory_after.bin (captured after purchasing an item in game).
Action Plan:
1. Run `python scripts/memory_diff.py memory_before.bin memory_after.bin --align 4 --struct PlayerInventory`.
2. Identify which offsets experienced an exact integer delta matching the gold price and item ID.
3. Synthesize both C++ struct and C# explicit struct layout definitions with exact [FieldOffset] attributes.
4. Formulate pointer chain traversal logic starting from the main engine base.
```

### Türkçe Prompt
```text
Görev: Dinamik bellek fark analizi yöntemiyle nesne yapısını ve net alan ofsetlerini çıkar.
Girdiler: memory_before.bin ve memory_after.bin (oyun içi eşya satın alımından hemen önce ve sonra).
Eylem Planı:
1. `python scripts/memory_diff.py memory_before.bin memory_after.bin --align 4 --struct PlayerInventory` komutunu çalıştır.
2. Altın fiyatı ve eşya kimliğiyle (ID) birebir eşleşen tamsayı farklarını (delta) tespit et.
3. Hem C++ struct hem de [FieldOffset] etiketlerine sahip C# explicit struct tanımlarını sentezle.
4. Ana motor taban adresinden başlayan işaretçi zinciri (pointer chain) çözümleme mantığını oluştur.
```

---

## 7. Multi-Engine Consensus Decompilation

### English Prompt
```text
Task: Arbitrate conflicting decompilation outputs between Ghidra and IDA Pro for a cryptographic hash loop.
Inputs: Ghidra decompilation snippet vs IDA Hex-Rays pseudocode snippet.
Action Plan:
1. Consult `references/decompilation-consensus.md`.
2. Compare variable lifecycles, loop boundary inequalities (< vs <=), and sign extensions.
3. Inspect raw opcode disassembly (e.g. movsx vs movzx, jl vs jle) to declare the ground truth.
4. Produce a certified, clean C# (.NET 8) implementation using ReadOnlySpan<byte>.
```

### Türkçe Prompt
```text
Görev: Kriptografik hash döngüsünde Ghidra ile IDA Pro arasındaki çelişkili dekompilasyon çıktılarını uzlaştır.
Girdiler: Ghidra dekompilasyon çıktısı ile IDA Hex-Rays pseudocode çıktısı.
Eylem Planı:
1. `references/decompilation-consensus.md` dokümanındaki konsensüs kurallarını uygula.
2. Değişken yaşam döngülerini, döngü sınır eşitsizliklerini (< ve <=) ve işaret genişletmelerini (sign extension) karşılaştır.
3. Kesin doğruyu belirlemek için ham makine kodundaki (assembly) opcodeları (movsx/movzx, jl/jle) incele.
4. ReadOnlySpan<byte> kullanan, hatasız ve temiz bir C# (.NET 8) metodunu teslim et.
```

---

## 8. Round-Trip Equivalence Verification

### English Prompt
```text
Task: Prove that the reconstructed decryption algorithm behaves with 100% equivalence to the native binary slice.
Action Plan:
1. Isolate the native machine code bytes from the target executable.
2. Compile the reconstructed C/C++ function into a dynamic test harness.
3. Synthesize 1,000 differential test vectors covering boundary limits (0, -1, INT_MAX, NULL) and randomized bytes.
4. Follow `references/verification-loop.md` to run the native slice in Unicorn Engine alongside the reconstructed function.
5. Provide a verification certificate proving 1,000 / 1,000 matches with zero deltas.
```

### Türkçe Prompt
```text
Görev: Yeniden inşa edilen şifre çözme algoritmasının orijinal ikili dilimle %100 aynı davrandığını matematiksel olarak ispatla.
Eylem Planı:
1. Orijinal çalıştırılabilir dosyadan ham makine kodu baytlarını izole et.
2. Yeniden yazılan C/C++ fonksiyonunu dinamik bir test kütüphanesine derle.
3. Sınır değerleri (0, -1, INT_MAX, NULL) ve rastgele baytları kapsayan 1.000 adet test vektörü üret.
4. `references/verification-loop.md` kılavuzunu izleyerek yerel dilimi Unicorn Engine üzerinde, yeni kodu ise test harness üzerinde çalıştır.
5. Sıfır fark ile 1.000 / 1.000 eşleşmeyi kanıtlayan doğrulama raporunu teslim et.
```

---

## 9. Wildcard Pattern & RIP-Relative Offset Hunting

### English Prompt
```text
Task: Dynamically resolve the global GameWorld singleton address across game patches using wildcard pattern scanning.
Target: GameClient-Win64-Shipping.exe
Action Plan:
1. Run `python skills/apex-re/scripts/sig_scan.py scan <binary> "48 8B 05 ? ? ? ? 48 85 C0" --rip 3 7`
2. Calculate target RVA = NextRIP + Displacement.
3. Consult `references/signature-and-pattern-scanning.md` for stable pattern synthesis.
4. Emit modern C++20 offset macros and C# (.NET 8) static accessors.
```

### Türkçe Prompt
```text
Görev: Güncellemeler sonrasında global GameWorld singleton adresini dinamik olarak tespit etmek için wildcard pattern taraması yap.
Hedef: GameClient-Win64-Shipping.exe
Eylem Planı:
1. `python skills/apex-re/scripts/sig_scan.py scan <binary> "48 8B 05 ? ? ? ? 48 85 C0" --rip 3 7` komutunu çalıştır.
2. Hedef RVA = NextRIP + Displacement formülüyle kesin sanal adresi hesapla.
3. Gelecek yamalarda bozulmayacak stabil imza sentezi için `references/signature-and-pattern-scanning.md` rehberini incele.
4. C++20 ofset makrolarını ve C# (.NET 8) statik sınıflarını üret.
```

---

## 10. VM Devirtualization & Backward Slicing

### English Prompt
```text
Task: Devirtualize a VMProtect / Themida bytecode execution trace and recover the clean mathematical algorithm.
Target: trace.log (execution trace of virtualized handler loop)
Action Plan:
1. Run `python skills/apex-re/scripts/vm_analyzer.py trace.log --slice rax`
2. Filter repetitive VIP incrementation and dispatcher jump table overhead.
3. Classify handlers into VPUSH, VPOP, and VALU operations per `references/vm-bytecode-analysis.md`.
4. Perform backward dependency slicing on RAX to extract the pure arithmetic formula.
5. Reconstruct high-level compilable C / C# code without virtual machine artifacts.
```

### Türkçe Prompt
```text
Görev: VMProtect / Themida sanallaştırılmış bytecode yürütme kaydını analiz et ve altındaki saf matematiksel algoritmayı kurtar.
Hedef: trace.log (sanallaştırılmış döngü yürütme izi)
Eylem Planı:
1. `python skills/apex-re/scripts/vm_analyzer.py trace.log --slice rax` komutunu çalıştır.
2. Tekrarlayan VIP artırma ve dispatcher sıçrama yükünü filtrele.
3. `references/vm-bytecode-analysis.md` rehberine göre handlerları VPUSH, VPOP ve VALU olarak sınıflandır.
4. RAX hedef kaydı üzerinde geriye dönük bağımlılık dilimlemesi (backward slicing) yaparak saf formülü izole et.
5. Sanal makine kalıntılarından arındırılmış, derlenebilir temiz C / C# kodunu teslim et.
```
