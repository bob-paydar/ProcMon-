# ProcMon — Windows Process Monitor / Task Killer

ProcMon is a lightweight Windows console utility written in modern C++17.  
It can list, find, monitor, and control running processes directly from the command line — no drivers or services required.

## ✨ Features

- **List running processes** (PID, PPID, CPU%, RSS memory, name, full path)
- **Find processes** by name or path pattern
- **Top-style monitor** with CPU usage sampling
- **Kill / Suspend / Resume** by PID or name
- **Tree mode** (`--tree`) to operate on a process and all of its children
- **Output formats**:
  - Human-readable table (default)
  - JSON (`--json` / `--json file.json`)
  - CSV (`--csv` / `--csv file.csv`)
- **UTF-8/Unicode support** for process names and paths
- Runs as a single executable, no installer or dependencies

## 📦 Build

Requirements:

- Windows 10 or newer
- Visual Studio 2019/2022 with C++ toolset

Build from the Developer Command Prompt:

```powershell
cl /EHsc /W4 /Zc:__cplusplus /std:c++17 ProcMon.cpp psapi.lib
```

This produces `ProcMon.exe`.

## 🚀 Usage

```
ProcMon.exe list [--json [file]] [--csv [file]]
ProcMon.exe find <pattern> [--json [file]] [--csv [file]]
ProcMon.exe top [--interval 1000] [--iterations 20]
ProcMon.exe kill <pid|name> [--tree]
ProcMon.exe suspend <pid|name> [--tree]
ProcMon.exe resume  <pid|name> [--tree]
ProcMon.exe help
```

### Examples

List all processes (table view):

```powershell
.\ProcMon.exe list
```

List all processes and export to JSON + CSV:

```powershell
.\ProcMon.exe list --json procs.json --csv procs.csv
```

Find Chrome processes:

```powershell
.\ProcMon.exe find chrome
```

Run a live top monitor (refresh every 500ms, 10 iterations):

```powershell
.\ProcMon.exe top --interval 500 --iterations 10
```

Kill Notepad by name (and its children):

```powershell
.\ProcMon.exe kill notepad --tree
```

Suspend/Resume by PID:

```powershell
.\ProcMon.exe suspend 1234
.\ProcMon.exe resume 1234
```

## ⚠️ Notes

- Some operations (kill/suspend/resume) require **Administrator privileges** for protected processes.
- CPU% is approximate — calculated over the sampling interval.
- JSON and CSV exports are UTF-8 encoded (with BOM).

## 📜 License

MIT License. See LICENSE for details.

---

👤 Author: **Bob Paydar**  
📧 Contact: `Bob.paydar@hp.com`
