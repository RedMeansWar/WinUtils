/*
 * ============================================================================
 * WinExtra.hpp
 * Part of the WinUtils project — Extended Windows utility namespaces
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
 *
 * USE AT YOUR OWN RISK.
 *
 * Some functions in this file (Firewall, Scheduler, Power plan management)
 * require Administrator privileges and modify system configuration.
 * The author accepts no responsibility for damages arising from use or misuse.
 *
 * ============================================================================
 *
 * Requires : Windows (Win32 API), C++17 or later, WinUtils.hpp
 * Reference: See README.md for full documentation
 *
 * ============================================================================
*/

#pragma once
#ifndef WIN_EXTRA_HPP
#define WIN_EXTRA_HPP

#ifndef WIN_UTILS_HPP
// ! WinHardware.hpp requires WinUtils.hpp — #include "WinUtils.hpp" first.
// ! This is to avoid circular dependencies, as WinUtils.hpp contains some basic utilities
// ! that WinHardware.hpp relies on. Please include WinUtils.hpp before including this file.
#include "WinUtils.hpp"
#endif

#include <netfw.h>
#include <taskschd.h>
#include <powrprof.h>
#include <evntprov.h>
#include <winevt.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "wevtapi.lib")

namespace WinUtils {

// ============================================================
//  SECTION E1 — Named Mutex (Single Instance Enforcement)
// ============================================================
namespace Mutex {

    /// Create or open a named mutex. Returns handle or nullptr.
    /// If alreadyExists is set to true, another instance is running.
    inline HANDLE Create(const std::string& name, bool* alreadyExists = nullptr) {
        HANDLE h = CreateMutexW(nullptr, TRUE, Str::ToWide(name).c_str());
        if (alreadyExists) *alreadyExists = (GetLastError() == ERROR_ALREADY_EXISTS);
        return h;
    }

    /// Enforce single instance — if another instance is running, return false.
    /// Pass the returned HANDLE to Release() on exit.
    inline bool EnforceSingleInstance(const std::string& name, HANDLE& outHandle) {
        bool exists = false;
        outHandle = Create(name, &exists);
        if (exists) {
            // Optionally bring the existing window to front
            HWND existing = Window::FindByPartialTitle("");
            if (existing) Window::BringToFront(existing);
            return false;
        }
        return true;
    }

    /// Release a mutex handle
    inline void Release(HANDLE h) {
        if (h) { ReleaseMutex(h); CloseHandle(h); }
    }

    /// Check if a named mutex already exists (another instance is running)
    inline bool IsRunning(const std::string& name) {
        HANDLE h = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, Str::ToWide(name).c_str());
        if (h) { CloseHandle(h); return true; }
        return false;
    }

} // namespace Mutex

// ============================================================
//  SECTION E2 — Named Pipes (Inter-Process Communication)
// ============================================================
namespace Pipe {

    /// Create a named pipe server. Returns handle or INVALID_HANDLE_VALUE.
    /// pipeName: e.g. "\\\\.\\pipe\\MyAppPipe"
    inline HANDLE CreateServer(const std::string& pipeName,
                                DWORD bufSize = 4096) {
        return CreateNamedPipeW(
            Str::ToWide(pipeName).c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            bufSize, bufSize, 0, nullptr);
    }

    /// Wait for a client to connect to the pipe (blocking)
    inline bool WaitForClient(HANDLE hPipe) {
        return ConnectNamedPipe(hPipe, nullptr) ||
               GetLastError() == ERROR_PIPE_CONNECTED;
    }

    /// Connect to an existing named pipe as a client
    inline HANDLE Connect(const std::string& pipeName, DWORD timeoutMs = 5000) {
        std::wstring wname = Str::ToWide(pipeName);
        if (!WaitNamedPipeW(wname.c_str(), timeoutMs)) return INVALID_HANDLE_VALUE;
        return CreateFileW(wname.c_str(),
            GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
    }

    /// Send a string message through a pipe
    inline bool Send(HANDLE hPipe, const std::string& message) {
        DWORD written = 0;
        return WriteFile(hPipe, message.c_str(),
            static_cast<DWORD>(message.size()), &written, nullptr) && written > 0;
    }

    /// Receive a string message from a pipe
    inline std::optional<std::string> Receive(HANDLE hPipe, DWORD bufSize = 4096) {
        std::vector<char> buf(bufSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, buf.data(), bufSize, &bytesRead, nullptr) || bytesRead == 0)
            return std::nullopt;
        return std::string(buf.data(), bytesRead);
    }

    /// Disconnect and close a pipe handle
    inline void Close(HANDLE hPipe) {
        if (hPipe && hPipe != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }

    /// Simple one-shot send to a pipe server (client side)
    inline bool QuickSend(const std::string& pipeName, const std::string& message) {
        HANDLE h = Connect(pipeName);
        if (h == INVALID_HANDLE_VALUE) return false;
        bool ok = Send(h, message);
        CloseHandle(h);
        return ok;
    }

} // namespace Pipe

// ============================================================
//  SECTION E3 — Windows Event Log
// ============================================================
namespace EventLog {

    enum class EventType { Info, Warning, Error, SuccessAudit, FailureAudit };

    /// Write an entry to the Windows Event Log
    /// source: your application name (register it first for best results)
    inline bool Write(const std::string& source, const std::string& message,
                      EventType type = EventType::Info, DWORD eventId = 1000) {
        HANDLE h = RegisterEventSourceW(nullptr, Str::ToWide(source).c_str());
        if (!h) return false;
        WORD wtype;
        switch (type) {
            case EventType::Warning:      wtype = EVENTLOG_WARNING_TYPE;       break;
            case EventType::Error:        wtype = EVENTLOG_ERROR_TYPE;         break;
            case EventType::SuccessAudit: wtype = EVENTLOG_AUDIT_SUCCESS;      break;
            case EventType::FailureAudit: wtype = EVENTLOG_AUDIT_FAILURE;      break;
            default:                      wtype = EVENTLOG_INFORMATION_TYPE;   break;
        }
        std::wstring wmsg = Str::ToWide(message);
        LPCWSTR msgs[] = { wmsg.c_str() };
        bool ok = ReportEventW(h, wtype, 0, eventId, nullptr, 1, 0, msgs, nullptr) != FALSE;
        DeregisterEventSource(h);
        return ok;
    }

    struct EventRecord {
        DWORD       eventId    = 0;
        std::string source;
        std::string message;
        std::string timeGenerated;
        WORD        type       = 0;
    };

    /// Read the last N entries from a Windows Event Log (e.g. "Application", "System")
    inline std::vector<EventRecord> Read(const std::string& logName, DWORD maxEntries = 50) {
        std::vector<EventRecord> result;
        HANDLE h = OpenEventLogW(nullptr, Str::ToWide(logName).c_str());
        if (!h) return result;
        DWORD bytesRead = 0, minRequired = 0;
        std::vector<BYTE> buf(65536);
        while (result.size() < maxEntries) {
            if (!ReadEventLogW(h, EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
                0, buf.data(), static_cast<DWORD>(buf.size()), &bytesRead, &minRequired)) {
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    buf.resize(minRequired); continue;
                }
                break;
            }
            BYTE* ptr = buf.data();
            BYTE* end = ptr + bytesRead;
            while (ptr < end && result.size() < maxEntries) {
                auto* rec = reinterpret_cast<EVENTLOGRECORD*>(ptr);
                EventRecord er;
                er.eventId = rec->EventID & 0xFFFF;
                er.type    = rec->EventType;
                // Source name is right after the struct
                er.source  = Str::ToNarrow(reinterpret_cast<wchar_t*>(ptr + sizeof(EVENTLOGRECORD)));
                // Timestamp
                time_t t = rec->TimeGenerated;
                char tbuf[32] = {};
                std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
                er.timeGenerated = tbuf;
                result.push_back(er);
                ptr += rec->Length;
            }
        }
        CloseEventLog(h);
        return result;
    }

    /// Clear a Windows Event Log (requires Admin)
    inline bool Clear(const std::string& logName) {
        HANDLE h = OpenEventLogW(nullptr, Str::ToWide(logName).c_str());
        if (!h) return false;
        bool ok = ClearEventLogW(h, nullptr) != FALSE;
        CloseEventLog(h);
        return ok;
    }

} // namespace EventLog

// ============================================================
//  SECTION E4 — Windows Firewall
// ============================================================
//  Requires Administrator privileges and COM initialization.
// ============================================================
namespace Firewall {

    /// Add an inbound firewall rule allowing a program through
    inline bool AllowProgram(const std::string& name, const std::string& exePath) {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        INetFwRules* pRules = nullptr;
        INetFwPolicy2* pPolicy = nullptr;
        bool ok = false;
        if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&pPolicy)))) return false;
        if (SUCCEEDED(pPolicy->get_Rules(&pRules))) {
            INetFwRule* pRule = nullptr;
            if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), nullptr,
                CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
                reinterpret_cast<void**>(&pRule)))) {
                pRule->put_Name(_bstr_t(Str::ToWide(name).c_str()));
                pRule->put_ApplicationName(_bstr_t(Str::ToWide(exePath).c_str()));
                pRule->put_Action(NET_FW_ACTION_ALLOW);
                pRule->put_Enabled(VARIANT_TRUE);
                pRule->put_Direction(NET_FW_RULE_DIR_IN);
                ok = SUCCEEDED(pRules->Add(pRule));
                pRule->Release();
            }
            pRules->Release();
        }
        pPolicy->Release();
        return ok;
    }

    /// Add an inbound firewall rule allowing a specific port
    inline bool AllowPort(const std::string& name, DWORD port,
                           bool tcp = true) {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        INetFwRules* pRules = nullptr;
        INetFwPolicy2* pPolicy = nullptr;
        bool ok = false;
        if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&pPolicy)))) return false;
        if (SUCCEEDED(pPolicy->get_Rules(&pRules))) {
            INetFwRule* pRule = nullptr;
            if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), nullptr,
                CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
                reinterpret_cast<void**>(&pRule)))) {
                std::wstring portStr = std::to_wstring(port);
                pRule->put_Name(_bstr_t(Str::ToWide(name).c_str()));
                pRule->put_Protocol(tcp ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP);
                pRule->put_LocalPorts(_bstr_t(portStr.c_str()));
                pRule->put_Action(NET_FW_ACTION_ALLOW);
                pRule->put_Enabled(VARIANT_TRUE);
                pRule->put_Direction(NET_FW_RULE_DIR_IN);
                ok = SUCCEEDED(pRules->Add(pRule));
                pRule->Release();
            }
            pRules->Release();
        }
        pPolicy->Release();
        return ok;
    }

    /// Remove a firewall rule by name
    inline bool RemoveRule(const std::string& name) {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        INetFwRules* pRules = nullptr;
        INetFwPolicy2* pPolicy = nullptr;
        bool ok = false;
        if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&pPolicy)))) return false;
        if (SUCCEEDED(pPolicy->get_Rules(&pRules))) {
            ok = SUCCEEDED(pRules->Remove(_bstr_t(Str::ToWide(name).c_str())));
            pRules->Release();
        }
        pPolicy->Release();
        return ok;
    }

    /// Enable or disable the Windows Firewall for all profiles
    inline bool SetEnabled(bool enabled) {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        INetFwPolicy2* pPolicy = nullptr;
        if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&pPolicy)))) return false;
        VARIANT_BOOL val = enabled ? VARIANT_TRUE : VARIANT_FALSE;
        pPolicy->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN,  val);
        pPolicy->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, val);
        pPolicy->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC,  val);
        pPolicy->Release();
        return true;
    }

} // namespace Firewall

// ============================================================
//  SECTION E5 — Task Scheduler
// ============================================================
//  Requires Administrator for system-level tasks.
// ============================================================
namespace Scheduler {

    /// Create a scheduled task that runs an executable at system startup
    inline bool CreateStartupTask(const std::string& taskName,
                                   const std::string& exePath,
                                   const std::string& args = "",
                                   bool runAsAdmin = false) {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        ITaskService* pSvc = nullptr;
        if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr,
            CLSCTX_INPROC_SERVER, IID_ITaskService,
            reinterpret_cast<void**>(&pSvc)))) return false;
        if (FAILED(pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
            pSvc->Release(); return false;
        }
        ITaskFolder* pFolder = nullptr;
        pSvc->GetFolder(_bstr_t(L"\\"), &pFolder);
        ITaskDefinition* pTask = nullptr;
        pSvc->NewTask(0, &pTask);
        // Set registration info
        IRegistrationInfo* pRegInfo = nullptr;
        pTask->get_RegistrationInfo(&pRegInfo);
        pRegInfo->put_Author(_bstr_t(L"WinUtils"));
        pRegInfo->Release();
        // Set trigger — logon trigger
        ITriggerCollection* pTriggers = nullptr;
        pTask->get_Triggers(&pTriggers);
        ITrigger* pTrigger = nullptr;
        pTriggers->Create(TASK_TRIGGER_LOGON, &pTrigger);
        pTrigger->Release(); pTriggers->Release();
        // Set action
        IActionCollection* pActions = nullptr;
        pTask->get_Actions(&pActions);
        IAction* pAction = nullptr;
        pActions->Create(TASK_ACTION_EXEC, &pAction);
        IExecAction* pExecAction = nullptr;
        pAction->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&pExecAction));
        pExecAction->put_Path(_bstr_t(Str::ToWide(exePath).c_str()));
        if (!args.empty())
            pExecAction->put_Arguments(_bstr_t(Str::ToWide(args).c_str()));
        pExecAction->Release(); pAction->Release(); pActions->Release();
        // Set principal (run level)
        IPrincipal* pPrincipal = nullptr;
        pTask->get_Principal(&pPrincipal);
        pPrincipal->put_RunLevel(runAsAdmin ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA);
        pPrincipal->Release();
        // Register task
        IRegisteredTask* pRegTask = nullptr;
        HRESULT hr = pFolder->RegisterTaskDefinition(
            _bstr_t(Str::ToWide(taskName).c_str()),
            pTask, TASK_CREATE_OR_UPDATE,
            _variant_t(), _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""), &pRegTask);
        if (pRegTask) pRegTask->Release();
        pTask->Release(); pFolder->Release(); pSvc->Release();
        return SUCCEEDED(hr);
    }

    /// Delete a scheduled task by name
    inline bool DeleteTask(const std::string& taskName) {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        ITaskService* pSvc = nullptr;
        if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr,
            CLSCTX_INPROC_SERVER, IID_ITaskService,
            reinterpret_cast<void**>(&pSvc)))) return false;
        pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        ITaskFolder* pFolder = nullptr;
        pSvc->GetFolder(_bstr_t(L"\\"), &pFolder);
        bool ok = SUCCEEDED(pFolder->DeleteTask(
            _bstr_t(Str::ToWide(taskName).c_str()), 0));
        pFolder->Release(); pSvc->Release();
        return ok;
    }

    /// Check if a scheduled task exists
    inline bool TaskExists(const std::string& taskName) {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        ITaskService* pSvc = nullptr;
        if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr,
            CLSCTX_INPROC_SERVER, IID_ITaskService,
            reinterpret_cast<void**>(&pSvc)))) return false;
        pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        ITaskFolder* pFolder = nullptr;
        pSvc->GetFolder(_bstr_t(L"\\"), &pFolder);
        IRegisteredTask* pTask = nullptr;
        bool exists = SUCCEEDED(pFolder->GetTask(
            _bstr_t(Str::ToWide(taskName).c_str()), &pTask));
        if (pTask) pTask->Release();
        pFolder->Release(); pSvc->Release();
        return exists;
    }

} // namespace Scheduler

// ============================================================
//  SECTION E6 — Windows Theme & Appearance
// ============================================================
namespace Theme {

    /// Check if Windows dark mode is enabled
    inline bool IsDarkMode() {
        return !Registry::IsLightMode();
    }

    /// Set dark or light mode
    inline bool SetDarkMode(bool dark) {
        return Registry::SetLightMode(!dark);
    }

    /// Get the current Windows accent color as COLORREF
    inline COLORREF GetAccentColor() {
        auto val = Registry::ReadDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\DWM", "ColorizationColor");
        if (!val) return RGB(0, 120, 215); // default Windows blue
        DWORD c = *val;
        // ColorizationColor is ARGB, convert to COLORREF (BGR)
        return RGB((c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF);
    }

    /// Get the current wallpaper path
    inline std::string GetWallpaper() {
        wchar_t buf[MAX_PATH] = {};
        SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, buf, 0);
        return Str::ToNarrow(buf);
    }

    /// Set the desktop wallpaper
    inline bool SetWallpaper(const std::string& path) {
        return SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0,
            const_cast<LPWSTR>(Str::ToWide(path).c_str()),
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE) != FALSE;
    }

    /// Get system DPI (96 = 100%, 120 = 125%, 144 = 150%)
    inline UINT GetSystemDPI() {
        HDC hdc = GetDC(nullptr);
        UINT dpi = static_cast<UINT>(GetDeviceCaps(hdc, LOGPIXELSX));
        ReleaseDC(nullptr, hdc);
        return dpi;
    }

    /// Check if transparency effects are enabled
    inline bool IsTransparencyEnabled() {
        auto val = Registry::ReadDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "EnableTransparency");
        return val.value_or(1) == 1;
    }

    /// Enable or disable transparency effects
    inline bool SetTransparencyEnabled(bool enabled) {
        return Registry::WriteDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "EnableTransparency", enabled ? 1 : 0);
    }

    /// Get current Windows theme name
    inline std::string GetCurrentTheme() {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz = sizeof(buf);
        RegGetValueW(HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes",
            L"CurrentTheme", RRF_RT_REG_SZ, nullptr, buf, &sz);
        return std::filesystem::path(Str::ToNarrow(buf)).stem().string();
    }

} // namespace Theme

// ============================================================
//  SECTION E7 — Power Management
// ============================================================
namespace PowerMgmt {

    /// Prevent the system from sleeping (call once, re-call to update)
    /// Flags: ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
    inline void PreventSleep(bool keepDisplayOn = false) {
        DWORD flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED;
        if (keepDisplayOn) flags |= ES_DISPLAY_REQUIRED;
        SetThreadExecutionState(flags);
    }

    /// Allow the system to sleep normally again
    inline void AllowSleep() {
        SetThreadExecutionState(ES_CONTINUOUS);
    }

    /// Send the system to sleep immediately
    inline bool Sleep() {
        return SetSuspendState(FALSE, FALSE, FALSE) != FALSE;
    }

    /// Hibernate the system
    inline bool Hibernate() {
        return SetSuspendState(TRUE, FALSE, FALSE) != FALSE;
    }

    struct PowerPlan {
        std::string name;
        std::string guid;
        bool        isActive = false;
    };

    /// Get all power plans
    inline std::vector<PowerPlan> GetPowerPlans() {
        std::vector<PowerPlan> result;
        GUID activePlan{};
        PowerGetActiveScheme(nullptr, reinterpret_cast<GUID**>(&activePlan));
        DWORD idx = 0;
        while (true) {
            GUID planGuid{};
            DWORD bufSize = sizeof(GUID);
            if (PowerEnumerate(nullptr, nullptr, nullptr,
                ACCESS_SCHEME, idx++, reinterpret_cast<UCHAR*>(&planGuid), &bufSize) != ERROR_SUCCESS)
                break;
            PowerPlan p;
            // Get plan friendly name
            DWORD nameSz = 0;
            PowerReadFriendlyName(nullptr, &planGuid, nullptr, nullptr, nullptr, &nameSz);
            if (nameSz > 0) {
                std::vector<UCHAR> nameBuf(nameSz);
                PowerReadFriendlyName(nullptr, &planGuid, nullptr, nullptr, nameBuf.data(), &nameSz);
                p.name = Str::ToNarrow(reinterpret_cast<wchar_t*>(nameBuf.data()));
            }
            // Format GUID
            wchar_t guidStr[64] = {};
            StringFromGUID2(planGuid, guidStr, 64);
            p.guid     = Str::ToNarrow(guidStr);
            p.isActive = (memcmp(&planGuid, &activePlan, sizeof(GUID)) == 0);
            result.push_back(p);
        }
        return result;
    }

    /// Set active power plan by name (partial match)
    inline bool SetPowerPlan(const std::string& planName) {
        std::string lower = planName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (auto& p : GetPowerPlans()) {
            std::string n = p.name;
            std::transform(n.begin(), n.end(), n.begin(), ::tolower);
            if (n.find(lower) != std::string::npos) {
                GUID planGuid{};
                CLSIDFromString(Str::ToWide(p.guid).c_str(), &planGuid);
                return PowerSetActiveScheme(nullptr, &planGuid) == ERROR_SUCCESS;
            }
        }
        return false;
    }

    inline bool SetHighPerformance() { return SetPowerPlan("High performance"); }
    inline bool SetBalanced()        { return SetPowerPlan("Balanced"); }
    inline bool SetPowerSaver()      { return SetPowerPlan("Power saver"); }

    /// Get current power plan name
    inline std::string GetActivePlanName() {
        for (auto& p : GetPowerPlans())
            if (p.isActive) return p.name;
        return {};
    }

    /// Check if system is plugged in
    inline bool IsPluggedIn() {
        SYSTEM_POWER_STATUS sps{};
        GetSystemPowerStatus(&sps);
        return sps.ACLineStatus == 1;
    }

} // namespace PowerMgmt

// ============================================================
//  SECTION E8 — Network Configuration
// ============================================================
namespace NetConfig {

    /// Get the current machine's hostname
    inline std::string GetHostname() {
        wchar_t buf[256] = {}; DWORD sz = 256;
        GetComputerNameExW(ComputerNameDnsHostname, buf, &sz);
        return Str::ToNarrow(buf);
    }

    /// Flush the DNS resolver cache
    inline bool FlushDNS() {
        return Process::Run("ipconfig.exe", "/flushdns", false, true);
    }

    /// Release and renew DHCP lease
    inline bool RenewDHCP(const std::string& adapterName = "") {
        bool ok = true;
        ok &= Process::Run("ipconfig.exe", "/release " + adapterName, false, true);
        ok &= Process::Run("ipconfig.exe", "/renew "  + adapterName, false, true);
        return ok;
    }

    /// Reset TCP/IP stack (requires Admin, reboot recommended)
    inline bool ResetTCPIP() {
        return Process::Run("netsh.exe", "int ip reset", true, true);
    }

    /// Reset Winsock catalog (requires Admin)
    inline bool ResetWinsock() {
        return Process::Run("netsh.exe", "winsock reset", true, true);
    }

    /// Open a specific port check (returns true if port is open on host)
    inline bool IsPortOpen(const std::string& host, DWORD port, DWORD timeoutMs = 2000) {
        auto result = Process::RunCapture(
            "powershell -Command \"(New-Object Net.Sockets.TcpClient).ConnectAsync('" +
            host + "'," + std::to_string(port) + ").Wait(" + std::to_string(timeoutMs) + ")\"");
        if (!result) return false;
        return Str::Trim(*result) == "True";
    }

    /// Get public IP address (requires internet)
    inline std::string GetPublicIP() {
        auto r = Net::HttpGet("https://api.ipify.org");
        return r ? Str::Trim(*r) : "";
    }

} // namespace NetConfig

} // namespace WinUtils

#endif // WIN_EXTRA_HPP

// ============================================================
//  QUICK REFERENCE — WinExtra.hpp
// ============================================================
//
//  Mutex::       Create, EnforceSingleInstance, Release, IsRunning
//
//  Pipe::        CreateServer, WaitForClient, Connect, Send,
//                Receive, Close, QuickSend
//
//  EventLog::    Write, Read, Clear
//
//  Firewall::    AllowProgram, AllowPort, RemoveRule, SetEnabled
//                (requires Admin)
//
//  Scheduler::   CreateStartupTask, DeleteTask, TaskExists
//                (requires Admin for system tasks)
//
//  Theme::       IsDarkMode, SetDarkMode, GetAccentColor,
//                GetWallpaper, SetWallpaper, GetSystemDPI,
//                IsTransparencyEnabled, SetTransparencyEnabled,
//                GetCurrentTheme
//
//  PowerMgmt::   PreventSleep, AllowSleep, Sleep, Hibernate,
//                GetPowerPlans, SetPowerPlan,
//                SetHighPerformance, SetBalanced, SetPowerSaver,
//                GetActivePlanName, IsPluggedIn
//
//  NetConfig::   GetHostname, FlushDNS, RenewDHCP,
//                ResetTCPIP, ResetWinsock,
//                IsPortOpen, GetPublicIP
//
// ============================================================