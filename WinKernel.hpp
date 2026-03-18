/*
 * ============================================================================
 * WinKernel.hpp
 * Part of the WinUtils project — Kernel driver interface & anti-cheat
 * ============================================================================
 *
 * Copyright (c) 2026 RedMeansWar
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *

 * ============================================================================
 * LEGAL NOTICE & ETHICAL USE POLICY
 * ============================================================================
 *
 * This file interfaces with the Windows kernel and contains anti-cheat
 * detection techniques used by professional game security systems.
 *
 * AUTHORIZED USE ONLY. Kernel drivers must be loaded only on systems you own
 * or have explicit written authorization to modify. Loading unsigned drivers
 * requires test signing mode which weakens system security — use in
 * controlled environments only.
 *
 * The anti-cheat techniques in this file are provided for legitimate game
 * developers and security researchers. Using them to BYPASS anti-cheat
 * systems rather than implement them is a violation of most game ToS agreements
 * and potentially applicable computer misuse law.
 *
 * THE AUTHOR ACCEPTS ZERO RESPONSIBILITY FOR MISUSE, BSOD, DATA LOSS, GAME
 * BANS, LEGAL CONSEQUENCES, OR ANY OTHER OUTCOME FROM USE OF THIS SOFTWARE.
 *
 * ============================================================================
 *
 * WARNING — KERNEL-LEVEL AND SECURITY-SENSITIVE FUNCTIONALITY.
 * USE AT YOUR OWN RISK.
 *
 * This file contains:
 *   - Usermode <-> kernel driver communication via DeviceIoControl
 *   - Driver loading/unloading via the Service Control Manager
 *   - Anti-cheat detection techniques used by EAC, BattlEye, and Vanguard
 *   - VM / sandbox detection
 *   - Memory integrity and module whitelist checking
 *
 * KERNEL DRIVER NOTES:
 *   Loading unsigned drivers requires either:
 *     a) A valid WHQL or EV code-signing certificate, OR
 *     b) Test signing mode:  bcdedit /set testsigning on  (then reboot)
 *   Without one of the above, Driver::Load will fail on modern Windows.
 *   Secure Boot must be disabled for test signing mode.
 *
 * The author accepts no responsibility for system instability, BSODs,
 * data loss, game bans, legal consequences, or any other outcome arising
 * from the use or misuse of this software.
 *
 * ============================================================================
 *
 * Requires : Windows (Win32 API), C++17 or later, WinUtils.hpp, WinPower.hpp
 * Reference: See README.md for full documentation
 *
 * ============================================================================
*/

#pragma once
#ifndef WIN_KERNEL_HPP
#define WIN_KERNEL_HPP

// Dependencies — included automatically if not already present
#include "WinUtils.hpp"
#include "WinPower.hpp"

#include <winternl.h>
#include <intrin.h>
#include <processthreadsapi.h>
#include <synchapi.h>
#pragma comment(lib, "ntdll.lib")

namespace WinUtils {

// ============================================================
//  SECTION K1 — Kernel Driver Interface
// ============================================================
//  Usermode communication with a kernel-mode .sys driver.
//  Your driver must create a device object with a known name
//  so this code can open a handle to it via CreateFile.
// ============================================================
namespace Driver {

    /// Load a kernel driver from a .sys file path via SCM.
    /// Requires Administrator + test signing or a signed driver.
    /// !! Can cause BSOD if the driver has bugs !!
    inline bool Load(const std::string& driverName, const std::string& sysPath) {
        Ownership::_EnablePrivilege(SE_LOAD_DRIVER_NAME);
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!hSCM) return false;
        std::wstring wName = Str::ToWide(driverName);
        std::wstring wPath = Str::ToWide(sysPath);
        SC_HANDLE hSvc = CreateServiceW(hSCM,
            wName.c_str(), wName.c_str(),
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            wPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!hSvc) {
            // Already exists — just open it
            hSvc = OpenServiceW(hSCM, wName.c_str(), SERVICE_ALL_ACCESS);
        }
        bool ok = false;
        if (hSvc) {
            ok = StartServiceW(hSvc, 0, nullptr) != FALSE ||
                 GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
        return ok;
    }

    /// Unload (stop and delete) a kernel driver service.
    /// !! Unloading a driver while it has open handles can BSOD !!
    inline bool Unload(const std::string& driverName) {
        Ownership::_EnablePrivilege(SE_LOAD_DRIVER_NAME);
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCM) return false;
        SC_HANDLE hSvc = OpenServiceW(hSCM, Str::ToWide(driverName).c_str(),
            SERVICE_STOP | DELETE);
        bool ok = false;
        if (hSvc) {
            SERVICE_STATUS ss{};
            ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
            ::Sleep(500);
            ok = DeleteService(hSvc) != FALSE;
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
        return ok;
    }

    /// Open a handle to a driver device object.
    /// devicePath: e.g. "\\\\.\\MyDriver"
    /// Returns INVALID_HANDLE_VALUE on failure.
    inline HANDLE Open(const std::string& devicePath) {
        return CreateFileW(
            Str::ToWide(devicePath).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    /// Send an IOCTL to a driver and optionally receive output.
    inline bool SendIOCTL(HANDLE hDriver, DWORD ioctlCode,
                           void* inBuf  = nullptr, DWORD inSize  = 0,
                           void* outBuf = nullptr, DWORD outSize = 0,
                           DWORD* bytesReturned = nullptr) {
        DWORD br = 0;
        return DeviceIoControl(hDriver, ioctlCode,
            inBuf, inSize, outBuf, outSize,
            bytesReturned ? bytesReturned : &br, nullptr) != FALSE;
    }

    /// Typed IOCTL helper — send a struct, receive a struct
    template<typename TIn, typename TOut>
    inline bool SendIOCTL(HANDLE hDriver, DWORD ioctlCode,
                           const TIn& input, TOut& output) {
        DWORD br = 0;
        return DeviceIoControl(hDriver, ioctlCode,
            const_cast<TIn*>(&input), sizeof(TIn),
            &output, sizeof(TOut), &br, nullptr) != FALSE;
    }

    /// RAII driver handle wrapper
    struct DriverHandle {
        HANDLE h = INVALID_HANDLE_VALUE;

        explicit DriverHandle(const std::string& devicePath) {
            h = Open(devicePath);
        }
        ~DriverHandle() {
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }

        bool IsValid() const { return h != INVALID_HANDLE_VALUE; }

        bool IOCTL(DWORD code,
                   void* in=nullptr, DWORD inSz=0,
                   void* out=nullptr, DWORD outSz=0) {
            return SendIOCTL(h, code, in, inSz, out, outSz);
        }

        template<typename TIn, typename TOut>
        bool IOCTL(DWORD code, const TIn& input, TOut& output) {
            return SendIOCTL<TIn,TOut>(h, code, input, output);
        }
    };

    /// Check if a kernel driver service is loaded and running
    inline bool IsLoaded(const std::string& driverName) {
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCM) return false;
        SC_HANDLE hSvc = OpenServiceW(hSCM, Str::ToWide(driverName).c_str(),
            SERVICE_QUERY_STATUS);
        if (!hSvc) { CloseServiceHandle(hSCM); return false; }
        SERVICE_STATUS ss{};
        QueryServiceStatus(hSvc, &ss);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return ss.dwCurrentState == SERVICE_RUNNING;
    }

} // namespace Driver

// ============================================================
//  SECTION K2 — Anti-Cheat Detection
// ============================================================
//  Usermode anti-cheat companion. Designed to work alongside
//  a kernel driver for complete coverage.
//  These are the same techniques used by EAC, BattlEye, Vanguard.
// ============================================================
namespace AntiCheat {

    // ----------------------------------------------------------
    //  Module / DLL Integrity
    // ----------------------------------------------------------

    /// Check all loaded modules in the current process against a whitelist.
    /// Returns a list of any modules NOT in the whitelist (suspicious DLLs).
    inline std::vector<std::string> ScanModules(
            const std::vector<std::string>& whitelist) {
        std::vector<std::string> suspicious;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (snap == INVALID_HANDLE_VALUE) return suspicious;
        MODULEENTRY32W me{ sizeof(MODULEENTRY32W) };
        if (Module32FirstW(snap, &me)) {
            do {
                std::string modName = Str::ToNarrow(me.szModule);
                std::string lower   = modName;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                bool found = false;
                for (auto& w : whitelist) {
                    std::string wl = w;
                    std::transform(wl.begin(), wl.end(), wl.begin(), ::tolower);
                    if (lower == wl) { found = true; break; }
                }
                if (!found) suspicious.push_back(modName);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return suspicious;
    }

    /// Hash-verify the current executable against a known-good hash.
    /// Returns false if the file has been tampered with.
    inline bool CheckSelfIntegrity(const std::string& expectedSHA256 = "") {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        auto content = File::ReadAll(Str::ToNarrow(path));
        if (!content) return false;
        std::string hash = Crypto::SHA256(*content);
        if (expectedSHA256.empty()) {
            // No expected hash — just return the computed hash via output
            // (first run: store this hash, subsequent runs: compare)
            return true;
        }
        return hash == expectedSHA256;
    }

    /// Get SHA256 hash of the current executable (for storing on first run)
    inline std::string GetSelfHash() {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        auto content = File::ReadAll(Str::ToNarrow(path));
        if (!content) return {};
        return Crypto::SHA256(*content);
    }

    /// Watch a memory region for unexpected writes.
    /// Calls onTamper if the region changes. Run on a dedicated thread.
    inline void WatchMemoryRegion(void* address, size_t size,
                                   std::function<void()> onTamper,
                                   bool* running = nullptr,
                                   DWORD intervalMs = 100) {
        std::vector<BYTE> snapshot(size);
        memcpy(snapshot.data(), address, size);
        static bool _defaultRunning = true;
        if (!running) running = &_defaultRunning;
        while (*running) {
            ::Sleep(intervalMs);
            if (memcmp(address, snapshot.data(), size) != 0) {
                if (onTamper) onTamper();
                // Update snapshot to avoid repeated triggers
                memcpy(snapshot.data(), address, size);
            }
        }
    }

    // ----------------------------------------------------------
    //  Speed Hack Detection
    // ----------------------------------------------------------

    struct SpeedHackDetector {
        std::chrono::steady_clock::time_point lastReal;
        uint64_t  lastTick     = 0;
        double    threshold    = 1.5; // flag if game time runs 1.5x faster than real time

        SpeedHackDetector() {
            lastReal = std::chrono::steady_clock::now();
            lastTick = GetTickCount64();
        }

        /// Call each frame. Returns true if speed hack detected.
        bool Check(double gameDeltaSeconds) {
            auto now     = std::chrono::steady_clock::now();
            double realDelta = std::chrono::duration<double>(now - lastReal).count();
            lastReal = now;
            if (realDelta <= 0.0) return false;
            double ratio = gameDeltaSeconds / realDelta;
            return ratio > threshold;
        }

        /// Alternative: compare GetTickCount64 drift
        bool CheckTickDrift(double gameDeltaSeconds) {
            uint64_t now   = GetTickCount64();
            double tickDelta = (now - lastTick) / 1000.0;
            lastTick = now;
            if (tickDelta <= 0.0) return false;
            return (gameDeltaSeconds / tickDelta) > threshold;
        }
    };

    // ----------------------------------------------------------
    //  Overlay / Screenshot Tool Detection
    // ----------------------------------------------------------

    /// Detect common screen overlay processes (cheat HUDs, aim overlays)
    inline std::vector<std::string> DetectOverlays() {
        static const std::vector<std::string> knownOverlays = {
            "fraps.exe", "afterburner.exe", "rivatuner.exe",
            "bandicam.exe", "obs32.exe", "obs64.exe",
            "xsplit.broadcaster.exe", "overwolf.exe",
            "discord.exe",  // legitimate but can overlay
            "playclaw.exe", "dxtory.exe", "mirillis.action.exe"
        };
        std::vector<std::string> found;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return found;
        PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(snap, &pe)) {
            do {
                std::string name = Str::ToNarrow(pe.szExeFile);
                std::string lower = name;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                for (auto& o : knownOverlays)
                    if (lower == o) { found.push_back(name); break; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return found;
    }

    /// Detect if any window with WS_EX_LAYERED | WS_EX_TRANSPARENT is
    /// sitting on top of the current process (classic cheat overlay signature)
    inline bool DetectTransparentOverlay() {
        struct State { HWND gameWnd; bool found; };
        wchar_t gameTitle[256] = {};
        GetConsoleTitleW(gameTitle, 256);
        State state{ FindWindowW(nullptr, gameTitle), false };
        EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
            auto* s = reinterpret_cast<State*>(lp);
            if (hwnd == s->gameWnd) return TRUE;
            LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
            if ((ex & WS_EX_LAYERED) && (ex & WS_EX_TRANSPARENT) && IsWindowVisible(hwnd)) {
                s->found = true; return FALSE;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&state));
        return state.found;
    }

    // ----------------------------------------------------------
    //  Virtual Machine / Sandbox Detection
    // ----------------------------------------------------------

    /// Check CPU vendor string via CPUID for known hypervisor signatures
    inline bool IsRunningInVM() {
        // Check hypervisor present bit (CPUID leaf 1, ECX bit 31)
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 1);
        if (cpuInfo[2] & (1 << 31)) return true; // hypervisor present bit

        // Check vendor strings of known hypervisors
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = {};
        memcpy(vendor,     &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);
        std::string vs(vendor, 12);
        return vs == "VMwareVMware" ||
               vs == "Microsoft Hv" ||
               vs == "KVMKVMKVM\0\0\0" ||
               vs == "VBoxVBoxVBox";
    }

    /// Check for known VM registry artifacts
    inline bool DetectVMRegistry() {
        static const std::vector<std::pair<HKEY,std::string>> keys = {
            { HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools" },
            { HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions" },
            { HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vboxguest" },
            { HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmhgfs" },
            { HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vmmouse" },
        };
        for (auto& [root, key] : keys)
            if (Registry::KeyExists(root, key)) return true;
        return false;
    }

    /// Check for VM-related running processes
    inline bool DetectVMProcesses() {
        static const std::vector<std::string> vmProcs = {
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
            "vboxservice.exe", "vboxtray.exe",
            "sandboxierpcss.exe", "sandboxiedcomlaunch.exe"
        };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
        bool found = false;
        if (Process32FirstW(snap, &pe)) {
            do {
                std::string name = Str::ToNarrow(pe.szExeFile);
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                for (auto& v : vmProcs)
                    if (name == v) { found = true; break; }
            } while (!found && Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return found;
    }

    /// All-in-one VM/sandbox check
    inline bool IsVirtualEnvironment() {
        return IsRunningInVM() || DetectVMRegistry() || DetectVMProcesses();
    }

    // ----------------------------------------------------------
    //  Timing & Anti-Tamper
    // ----------------------------------------------------------

    /// Detect if execution time between two points is suspiciously long
    /// (suggests single-stepping in a debugger)
    inline bool DetectSingleStep(DWORD expectedMaxMs = 50) {
        auto start = std::chrono::steady_clock::now();
        volatile int dummy = 0;
        for (int i = 0; i < 1000; ++i) dummy += i; // known-duration work
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        return elapsed > static_cast<long long>(expectedMaxMs);
    }

    /// Check if the process has been running unrealistically long
    /// compared to its own internal tick counter (time manipulation)
    inline bool DetectTimeManipulation() {
        FILETIME create{}, exit{}, kernel{}, user{};
        GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user);
        ULARGE_INTEGER c; c.LowPart = create.dwLowDateTime; c.HighPart = create.dwHighDateTime;
        FILETIME now{}; GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER n; n.LowPart = now.dwLowDateTime; n.HighPart = now.dwHighDateTime;
        uint64_t wallMs  = (n.QuadPart - c.QuadPart) / 10000;
        uint64_t tickMs  = GetTickCount64();
        // If system tick counter is more than 10% ahead of wall clock, something is off
        return tickMs > wallMs * 1.1;
    }

    // ----------------------------------------------------------
    //  Convenience — Run All Checks
    // ----------------------------------------------------------

    struct ScanResult {
        bool          debuggerDetected    = false;
        bool          vmDetected          = false;
        bool          overlayDetected     = false;
        bool          integrityFailed     = false;
        bool          timingAnomalies     = false;
        std::vector<std::string> suspiciousModules;
        std::vector<std::string> overlayProcesses;
    };

    /// Run all anti-cheat checks and return a full report.
    /// whitelist: module names that are allowed to be loaded.
    inline ScanResult RunFullScan(
            const std::vector<std::string>& moduleWhitelist = {},
            const std::string& expectedHash = "") {
        ScanResult r;
        r.debuggerDetected = AntiDebug::AnyDebuggerDetected();
        r.vmDetected       = IsVirtualEnvironment();
        r.overlayProcesses = DetectOverlays();
        r.overlayDetected  = !r.overlayProcesses.empty() || DetectTransparentOverlay();
        if (!moduleWhitelist.empty())
            r.suspiciousModules = ScanModules(moduleWhitelist);
        if (!expectedHash.empty())
            r.integrityFailed = !CheckSelfIntegrity(expectedHash);
        r.timingAnomalies  = DetectSingleStep() || DetectTimeManipulation();
        return r;
    }

    /// Returns true if any check in the scan result failed
    inline bool IsCheating(const ScanResult& r) {
        return r.debuggerDetected  ||
               r.vmDetected        ||
               r.overlayDetected   ||
               r.integrityFailed   ||
               r.timingAnomalies   ||
               !r.suspiciousModules.empty();
    }

} // namespace AntiCheat

} // namespace WinUtils

#endif // WIN_KERNEL_HPP

// ============================================================
//  QUICK REFERENCE — WinKernel.hpp
// ============================================================
//
//  Driver::      Load, Unload, Open, SendIOCTL,
//                DriverHandle (RAII), IsLoaded
//
//  AntiCheat::   ScanModules(whitelist)
//                CheckSelfIntegrity(expectedHash)
//                GetSelfHash()
//                WatchMemoryRegion(addr, size, onTamper, running)
//                SpeedHackDetector .Check() / .CheckTickDrift()
//                DetectOverlays()
//                DetectTransparentOverlay()
//                IsRunningInVM()
//                DetectVMRegistry()
//                DetectVMProcesses()
//                IsVirtualEnvironment()
//                DetectSingleStep()
//                DetectTimeManipulation()
//                RunFullScan(whitelist, expectedHash) -> ScanResult
//                IsCheating(scanResult)
//
// ============================================================