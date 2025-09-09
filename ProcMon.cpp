// Process Monitor / Task Killer (Console, C++17, UNICODE)
// Build (Developer Command Prompt):
//   cl /EHsc /W4 /Zc:__cplusplus /std:c++17 ProcMon.cpp psapi.lib
//
// Commands:
//   ProcMon.exe list [--json [file]] [--csv [file]]
//   ProcMon.exe find <pattern> [--json [file]] [--csv [file]]
//   ProcMon.exe top [--interval 1000] [--iterations 20]
//   ProcMon.exe kill <pid|name> [--tree]
//   ProcMon.exe suspend <pid|name> [--tree]
//   ProcMon.exe resume  <pid|name> [--tree]
//   ProcMon.exe help
//
// Notes:
//   - Some actions require Administrator.
//   - CPU% is approximate over the sampling interval.

#define UNICODE
#define _UNICODE
#ifndef NOMINMAX
#define NOMINMAX          // avoid Windows' min/max macros breaking std::max
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <memory>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <cwctype>
#include <cstdlib>   // system("cls")

#pragma comment(lib, "psapi.lib")

#ifndef PROCESS_SUSPEND_RESUME
// Some SDKs don't define this
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

// ------------------------------ Utils
static bool g_verbose = false;

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

bool IContains(const std::wstring& hay, const std::wstring& needle) {
    return ToLower(hay).find(ToLower(needle)) != std::wstring::npos;
}

std::wstring LastErrorMessage(DWORD err = GetLastError()) {
    if (err == 0) return L"OK";
    LPWSTR buf = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, nullptr);
    std::wstring msg = (len && buf) ? std::wstring(buf, len) : L"(unknown)";
    if (buf) LocalFree(buf);
    while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n')) msg.pop_back();
    return msg;
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD sz = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz);
    CloseHandle(token);
    return ok && elev.TokenIsElevated;
}

// ------------------------------ Nt Suspend/Resume (optional)
using NtSuspendProcess_t = LONG(WINAPI*)(HANDLE);
using NtResumeProcess_t = LONG(WINAPI*)(HANDLE);
NtSuspendProcess_t pNtSuspendProcess = nullptr;
NtResumeProcess_t  pNtResumeProcess = nullptr;

void LoadNtFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    pNtSuspendProcess = reinterpret_cast<NtSuspendProcess_t>(GetProcAddress(ntdll, "NtSuspendProcess"));
    pNtResumeProcess = reinterpret_cast<NtResumeProcess_t>(GetProcAddress(ntdll, "NtResumeProcess"));
}

// ------------------------------ Model structs
struct ProcInfo {
    DWORD pid{};
    DWORD ppid{};
    std::wstring name;      // exe name
    std::wstring path;      // full path (best effort)
    SIZE_T workingSet{};    // bytes
    ULONGLONG cpu100ns{};   // used between samples
    double cpuPercent{};    // computed
    bool wow64{ false };
};

struct Args {
    std::wstring cmd;
    std::map<std::wstring, std::wstring> kv;  // options and (optional) values
    std::vector<std::wstring> pos;           // positional args
    bool json{ false };                         // request JSON output (console or file)
    bool csv{ false };                          // request CSV output (console or file)
    std::wstring jsonFile;                    // if non-empty, write JSON to this file
    std::wstring csvFile;                     // if non-empty, write CSV to this file
};

Args ParseArgs(int argc, wchar_t** argv) {
    Args a;
    if (argc >= 2) a.cmd = ToLower(argv[1]);
    for (int i = 2; i < argc; ++i) {
        std::wstring s = argv[i];
        if (s.rfind(L"--", 0) == 0) {
            auto eq = s.find(L'=');
            std::wstring key = ToLower(eq == std::wstring::npos ? s.substr(2) : s.substr(2, eq - 2));
            std::wstring val;
            bool hasVal = false;
            if (eq == std::wstring::npos) {
                // try to read next arg as value if it's not another flag
                if (i + 1 < argc && argv[i + 1][0] != L'-') { val = argv[++i]; hasVal = true; }
                else { val = L"true"; }
            }
            else {
                val = s.substr(eq + 1); hasVal = true;
            }

            if (key == L"json") {
                a.json = true;
                if (hasVal && val != L"true") a.jsonFile = val;
            }
            else if (key == L"csv") {
                a.csv = true;
                if (hasVal && val != L"true") a.csvFile = val;
            }
            else if (key == L"verbose") {
                g_verbose = true;
            }
            else {
                a.kv[key] = val;
            }
        }
        else {
            a.pos.push_back(s);
        }
    }
    return a;
}

// ------------------------------ Enumerate processes
std::vector<ProcInfo> SnapshotProcesses() {
    std::vector<ProcInfo> v;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return v;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.ppid = pe.th32ParentProcessID;
            pi.name = pe.szExeFile;
            v.push_back(std::move(pi));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // Augment: path, memory, WOW64
    for (auto& pi : v) {
        if (pi.pid == 0) continue; // System Idle
        DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        HANDLE h = OpenProcess(access, FALSE, pi.pid);
        if (h) {
            // Path
            wchar_t buf[MAX_PATH * 4];
            DWORD sz = (DWORD)(MAX_PATH * 4);
            if (QueryFullProcessImageNameW(h, 0, buf, &sz)) pi.path.assign(buf, sz);
            // Memory
            PROCESS_MEMORY_COUNTERS_EX pmc{};
            if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                pi.workingSet = pmc.WorkingSetSize;
            }
            // Wow64
            BOOL iswow64 = FALSE;
            IsWow64Process(h, &iswow64);
            pi.wow64 = (iswow64 == TRUE);
            CloseHandle(h);
        }
    }
    return v;
}

// CPU times helpers
bool GetTimesForProcess(DWORD pid, ULONGLONG& kernelUser100ns) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return false;
    FILETIME ct, et, kt, ut;
    BOOL ok = GetProcessTimes(h, &ct, &et, &kt, &ut);
    CloseHandle(h);
    if (!ok) return false;
    ULARGE_INTEGER k; k.LowPart = kt.dwLowDateTime; k.HighPart = kt.dwHighDateTime;
    ULARGE_INTEGER u; u.LowPart = ut.dwLowDateTime; u.HighPart = ut.dwHighDateTime;
    kernelUser100ns = k.QuadPart + u.QuadPart; // 100ns units
    return true;
}

ULONGLONG GetSystemTime100ns() {
    FILETIME idle, kernel, user;
    GetSystemTimes(&idle, &kernel, &user);
    ULARGE_INTEGER k; k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
    ULARGE_INTEGER u; u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
    return k.QuadPart + u.QuadPart;
}

// Fill CPU% over intervalMs
void ComputeCpu(std::vector<ProcInfo>& procs, DWORD intervalMs) {
    // Baseline
    ULONGLONG sys0 = GetSystemTime100ns();
    std::unordered_map<DWORD, ULONGLONG> p0;
    for (auto& p : procs) {
        ULONGLONG t{};
        if (GetTimesForProcess(p.pid, t)) p0[p.pid] = t;
    }
    Sleep(intervalMs);
    // Second sample
    ULONGLONG sys1 = GetSystemTime100ns();
    ULONGLONG sysDelta = (sys1 > sys0) ? (sys1 - sys0) : 1;
    for (auto& p : procs) {
        ULONGLONG t1{};
        if (!GetTimesForProcess(p.pid, t1)) { p.cpuPercent = 0.0; continue; }
        auto it = p0.find(p.pid);
        if (it == p0.end()) { p.cpuPercent = 0.0; continue; }
        ULONGLONG pd = (t1 > it->second) ? (t1 - it->second) : 0;
        // Normalize to percentage across all logical CPUs
        p.cpuPercent = 100.0 * (double)pd / (double)sysDelta;
        p.cpu100ns = pd;
    }
}

// ------------------------------ Tree handling
std::unordered_map<DWORD, std::vector<DWORD>> BuildChildrenMap(const std::vector<ProcInfo>& v) {
    std::unordered_map<DWORD, std::vector<DWORD>> ch;
    for (auto& p : v) ch[p.ppid].push_back(p.pid);
    return ch;
}

void CollectTree(DWORD rootPid, const std::unordered_map<DWORD, std::vector<DWORD>>& ch, std::vector<DWORD>& out) {
    out.push_back(rootPid);
    auto it = ch.find(rootPid);
    if (it == ch.end()) return;
    for (DWORD c : it->second) CollectTree(c, ch, out);
}

// ------------------------------ Output helpers
std::wstring HumanSize(SIZE_T b) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
    double d = (double)b; int u = 0;
    while (d >= 1024.0 && u < 3) { d /= 1024.0; ++u; }
    std::wstringstream ss; ss << std::fixed << std::setprecision(u ? 1 : 0) << d << L" " << units[u];
    return ss.str();
}

std::wstring JsonEscape(const std::wstring& s) {
    std::wstringstream o;
    for (wchar_t c : s) {
        switch (c) {
        case L'"': o << L"\\\""; break;
        case L'\\':o << L"\\\\"; break;
        case L'\b':o << L"\\b";  break;
        case L'\f':o << L"\\f";  break;
        case L'\n':o << L"\\n";  break;
        case L'\r':o << L"\\r";  break;
        case L'\t':o << L"\\t";  break;
        default:
            if (c < 32) { o << L"\\u" << std::setw(4) << std::setfill(L'0') << std::hex << (int)c << std::dec; }
            else o << c;
        }
    }
    return o.str();
}

// Build JSON for a list of processes
std::wstring BuildJson(const std::vector<ProcInfo>& v) {
    std::wstringstream w;
    w << L"{\"processes\":[";
    for (size_t i = 0; i < v.size(); ++i) {
        const auto& p = v[i];
        w << L"{"
            << L"\"pid\":" << p.pid << L","
            << L"\"ppid\":" << p.ppid << L","
            << L"\"name\":\"" << JsonEscape(p.name) << L"\","
            << L"\"path\":\"" << JsonEscape(p.path) << L"\","
            << L"\"rss_bytes\":" << p.workingSet << L","
            << L"\"cpu_pct\":" << std::fixed << std::setprecision(2) << p.cpuPercent
            << L"}" << (i + 1 < v.size() ? L"," : L"");
    }
    w << L"]}\n";
    return w.str();
}

std::wstring CsvEscape(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 8);
    for (wchar_t c : s) {
        if (c == L'"') out += L"\"\"";
        else out += c;
    }
    return out;
}

// Build CSV (UTF-8 friendly; we’ll convert when writing)
std::wstring BuildCsv(const std::vector<ProcInfo>& v) {
    std::wstringstream w;
    w << L"PID,PPID,CPU_PCT,RSS_BYTES,Name,Path\n";
    for (const auto& p : v) {
        auto q = [&](const std::wstring& s) { return L"\"" + CsvEscape(s) + L"\""; };
        w << p.pid << L"," << p.ppid << L","
            << std::fixed << std::setprecision(2) << p.cpuPercent << L","
            << p.workingSet << L"," << q(p.name) << L"," << q(p.path) << L"\n";
    }
    return w.str();
}

// Convert UTF-16 -> UTF-8
std::string WToUtf8(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string out; out.resize(len);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &out[0], len, nullptr, nullptr);
    return out;
}

bool WriteTextFileUtf8(const std::wstring& path, const std::wstring& content, bool withBOM = true) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    if (withBOM) {
        static const unsigned char bom[3] = { 0xEF,0xBB,0xBF };
        ofs.write((const char*)bom, 3);
    }
    std::string u8 = WToUtf8(content);
    ofs.write(u8.data(), (std::streamsize)u8.size());
    return true;
}

void PrintHelp() {
    std::wcout <<
        L"Process Monitor / Task Killer\n"
        L"\n"
        L"USAGE:\n"
        L"  ProcMon.exe list [--json [file]] [--csv [file]]\n"
        L"  ProcMon.exe find <pattern> [--json [file]] [--csv [file]]\n"
        L"  ProcMon.exe top [--interval 1000] [--iterations 20]\n"
        L"  ProcMon.exe kill <pid|name> [--tree]\n"
        L"  ProcMon.exe suspend <pid|name> [--tree]\n"
        L"  ProcMon.exe resume  <pid|name> [--tree]\n"
        L"  ProcMon.exe help\n"
        L"\n"
        L"OUTPUT MODES:\n"
        L"  --json           print JSON to console\n"
        L"  --json <file>    write JSON to file (UTF-8) and still show table\n"
        L"  --csv            print CSV to console\n"
        L"  --csv <file>     write CSV to file (UTF-8) and still show table\n"
        L"\n"
        L"NOTES:\n"
        L"  - Admin is required to control some protected processes.\n"
        L"  - top shows an approximate CPU%% per process.\n";
}

void PrintTable(const std::vector<ProcInfo>& v) {
    std::wcout << L"PID     PPID    CPU%   RSS        Name\n";
    for (const auto& p : v) {
        std::wcout << std::setw(7) << p.pid << L" "
            << std::setw(7) << p.ppid << L" "
            << std::setw(5) << std::fixed << std::setprecision(1) << p.cpuPercent << L" "
            << std::setw(10) << HumanSize(p.workingSet) << L" "
            << p.name << L"\n";
        if (!p.path.empty())
            std::wcout << L"        Path: " << p.path << L"\n";
    }
}

void MaybeEmitJsonCsv(const std::vector<ProcInfo>& v, const Args& args) {
    if (args.json) {
        auto j = BuildJson(v);
        if (!args.jsonFile.empty()) {
            if (WriteTextFileUtf8(args.jsonFile, j))
                std::wcout << L"[json] wrote " << args.jsonFile << L"\n";
            else
                std::wcerr << L"[json] failed writing " << args.jsonFile << L": " << LastErrorMessage() << L"\n";
        }
        else {
            std::wcout << j;
        }
    }
    if (args.csv) {
        auto c = BuildCsv(v);
        if (!args.csvFile.empty()) {
            if (WriteTextFileUtf8(args.csvFile, c))
                std::wcout << L"[csv] wrote " << args.csvFile << L"\n";
            else
                std::wcerr << L"[csv] failed writing " << args.csvFile << L": " << LastErrorMessage() << L"\n";
        }
        else {
            std::wcout << c;
        }
    }
}

// ------------------------------ Open by PID or Name
std::vector<DWORD> PidsByName(const std::vector<ProcInfo>& v, const std::wstring& nameOrPattern) {
    std::vector<DWORD> pids;
    for (auto& p : v) {
        if (IContains(p.name, nameOrPattern) || IContains(p.path, nameOrPattern))
            pids.push_back(p.pid);
    }
    return pids;
}

bool ParseUint(const std::wstring& s, DWORD& out) {
    if (s.empty()) return false;
    wchar_t* end = nullptr;
    unsigned long v = wcstoul(s.c_str(), &end, 10);
    if (end && *end == 0) { out = (DWORD)v; return true; }
    return false;
}

// ------------------------------ Actions
bool TerminatePid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) { std::wcerr << L"OpenProcess(TERMINATE) failed PID " << pid << L": " << LastErrorMessage() << L"\n"; return false; }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    if (!ok) { std::wcerr << L"TerminateProcess failed PID " << pid << L": " << LastErrorMessage() << L"\n"; return false; }
    return true;
}

bool SuspendPid(DWORD pid) {
    if (!pNtSuspendProcess) { std::wcerr << L"Suspend not available on this system.\n"; return false; }
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) { std::wcerr << L"OpenProcess(SUSPEND) failed PID " << pid << L": " << LastErrorMessage() << L"\n"; return false; }
    LONG st = pNtSuspendProcess(h);
    CloseHandle(h);
    if (st != 0) { std::wcerr << L"NtSuspendProcess failed PID " << pid << L" (NTSTATUS=" << std::hex << st << std::dec << L")\n"; return false; }
    return true;
}

bool ResumePid(DWORD pid) {
    if (!pNtResumeProcess) { std::wcerr << L"Resume not available on this system.\n"; return false; }
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) { std::wcerr << L"OpenProcess(RESUME) failed PID " << pid << L": " << LastErrorMessage() << L"\n"; return false; }
    LONG st = pNtResumeProcess(h);
    CloseHandle(h);
    if (st != 0) { std::wcerr << L"NtResumeProcess failed PID " << pid << L" (NTSTATUS=" << std::hex << st << std::dec << L")\n"; return false; }
    return true;
}

// ------------------------------ Main
int wmain(int argc, wchar_t** argv) {
    std::ios::sync_with_stdio(false);
    LoadNtFunctions();
    auto args = ParseArgs(argc, argv);

    if (args.cmd.empty() || args.cmd == L"help" || args.cmd == L"--help" || args.cmd == L"-h") {
        PrintHelp();
        return 0;
    }

    if (args.cmd == L"list") {
        auto v = SnapshotProcesses();
        // quick CPU sample (200ms)
        ComputeCpu(v, 200);
        std::sort(v.begin(), v.end(), [](const ProcInfo& a, const ProcInfo& b) {
            if (a.cpuPercent != b.cpuPercent) return a.cpuPercent > b.cpuPercent;
            return a.workingSet > b.workingSet;
            });

        // Always show table
        PrintTable(v);
        // And emit JSON/CSV as requested (console or file)
        MaybeEmitJsonCsv(v, args);
        return 0;
    }

    if (args.cmd == L"find") {
        if (args.pos.empty()) { std::wcerr << L"find requires <pattern>\n"; return 1; }
        auto v = SnapshotProcesses();
        ComputeCpu(v, 200);
        std::vector<ProcInfo> out;
        for (auto& p : v) {
            if (IContains(p.name, args.pos[0]) || IContains(p.path, args.pos[0])) out.push_back(p);
        }
        std::sort(out.begin(), out.end(), [](const ProcInfo& a, const ProcInfo& b) {
            if (a.cpuPercent != b.cpuPercent) return a.cpuPercent > b.cpuPercent;
            return a.workingSet > b.workingSet;
            });

        PrintTable(out);
        MaybeEmitJsonCsv(out, args);
        return 0;
    }

    if (args.cmd == L"top") {
        DWORD interval = 1000;
        int iterations = 20;
        if (args.kv.count(L"interval")) interval = (DWORD)((std::max)(100, _wtoi(args.kv[L"interval"].c_str())));
        if (args.kv.count(L"iterations")) iterations = (std::max)(1, _wtoi(args.kv[L"iterations"].c_str()));

        for (int i = 0; i < iterations; ++i) {
            auto v = SnapshotProcesses();
            ComputeCpu(v, interval);
            std::sort(v.begin(), v.end(), [](const ProcInfo& a, const ProcInfo& b) {
                if (a.cpuPercent != b.cpuPercent) return a.cpuPercent > b.cpuPercent;
                return a.workingSet > b.workingSet;
                });
            system("cls");
            std::wcout << L"top (iter " << (i + 1) << L"/" << iterations << L", interval " << interval << L" ms)\n";
            PrintTable(v);
        }
        return 0;
    }

    if (args.cmd == L"kill" || args.cmd == L"suspend" || args.cmd == L"resume") {
        if (args.pos.empty()) { std::wcerr << args.cmd << L" requires <pid|name>\n"; return 1; }
        bool tree = args.kv.count(L"tree") > 0;
        auto snap = SnapshotProcesses();
        auto ch = BuildChildrenMap(snap);
        auto pids = [&]() {
            DWORD pid{};
            if (ParseUint(args.pos[0], pid)) return std::vector<DWORD>{pid};
            return PidsByName(snap, args.pos[0]);
            }();
        if (pids.empty()) { std::wcerr << L"No process matched.\n"; return 2; }

        std::vector<DWORD> victims;
        for (DWORD pid : pids) {
            if (tree) {
                CollectTree(pid, ch, victims);
            }
            else {
                victims.push_back(pid);
            }
        }
        // De-dup and sort reverse (children first)
        std::sort(victims.begin(), victims.end());
        victims.erase(std::unique(victims.begin(), victims.end()), victims.end());

        int ok = 0, fail = 0;
        for (auto it = victims.rbegin(); it != victims.rend(); ++it) {
            DWORD pid = *it;
            bool res = false;
            if (args.cmd == L"kill")    res = TerminatePid(pid);
            if (args.cmd == L"suspend") res = SuspendPid(pid);
            if (args.cmd == L"resume")  res = ResumePid(pid);
            if (res) { ++ok; if (g_verbose) std::wcout << args.cmd << L" OK pid=" << pid << L"\n"; }
            else { ++fail; }
        }
        std::wcout << args.cmd << L": OK=" << ok << L" FAIL=" << fail << L"\n";
        if (!IsElevated())
            std::wcout << L"(Tip: some targets require Administrator.)\n";
        return (fail == 0) ? 0 : 3;
    }

    std::wcerr << L"Unknown command. Use: help\n";
    return 1;
}
