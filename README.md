# Manual DLL Injector 🚀

Welcome to the Manual DLL Injector — a lightweight tool that manually maps a DLL into a target process without using LoadLibrary!

This project recreates part of the Windows loader's behavior by parsing PE headers, fixing relocations, handling TLS callbacks, and resolving imports — completely manually.

---

## ✅ Status: Fully working and ready for use!

---

## ✨ Features

- Find a target process by its name.
- Read a DLL file directly from disk.
- Parse the full PE structure (DOS Header, NT Headers, Sections).
- Allocate memory inside the target process manually.
- Map each section (.text, .data, .reloc, etc.) to the correct location.
- Fix relocations when the base address doesn't match.
- Handle TLS callbacks (Thread Local Storage).
- Resolve the Import Address Table (IAT) manually.
- No LoadLibrary or remote thread creation — everything is custom and controlled.

---

## 🛠️ How It Works

1. Find the target process by name using `CreateToolhelp32Snapshot`.
2. Read the DLL from disk into a local memory buffer.
3. Allocate executable memory inside the target process with `VirtualAllocEx`.
4. Copy each section from the local buffer into the allocated memory.
5. Apply relocations if the base address has changed.
6. Handle TLS callbacks (coming soon).
7. Resolve imports manually (coming soon).

---

## 🚀 Usage

```bash
ManualMapper.exe [TargetProcessName.exe] [YourDll.dll]
```

**Example:**

```bash
ManualMapper.exe notepad.exe mydll.dll
```

---

## 📋 Requirements

- Windows OS (x86 or x64)
- Visual Studio / GCC
- Administrator rights (recommended for some processes)

---

## ⚠️ Disclaimer

This project is for educational purposes only.  
Use responsibly.  
Injecting into other processes without permission can violate software terms of service and/or laws.

---

## ❤️ Credits

Written from scratch with love for Windows internals and reverse engineering.  
If you find this project useful, consider giving it a ⭐ star!
