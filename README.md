# WinUtils
### A Comprehensive Windows Utility Header Library

**Copyright (c) 2026 RedMeansWar** — MIT License

> **USE AT YOUR OWN RISK.**
> This software interacts directly with the Windows operating system.
> The author accepts no responsibility for damages arising from its use or misuse.
> You are solely responsible for ensuring your use is lawful and authorized.

---

## Overview

WinUtils is a header-only Windows utility library for C++17. No external dependencies — everything runs on the Win32 API and Windows CNG. Drop the headers you need into your project and go.

| File | Purpose | Admin Required |
|------|---------|---------------|
| `WinUtils.hpp` | General-purpose utilities | No |
| `WinHardware.hpp` | Hardware & system information | Some queries |
| `WinExtra.hpp` | Extended utilities (pipes, firewall, scheduler, etc.) | Some functions |
| `WinPower.hpp` | Low-level system & security utilities | Most functions |
| `WinKernel.hpp` | Kernel driver interface & anti-cheat | Yes |

### Include Order
```cpp
#include "WinUtils.hpp"       // always first — others depend on it
#include "WinHardware.hpp"    // hardware queries (optional)
#include "WinExtra.hpp"       // extra utilities (optional)
#include "WinPower.hpp"       // low-level / admin (optional)
#include "WinKernel.hpp"      // kernel + anti-cheat (requires WinUtils + WinPower)
```

## ⚠️ Legal Disclaimer & Ethical Use Policy

**READ THIS BEFORE USING THIS LIBRARY.**

Copyright (c) 2026 RedMeansWar. This software is provided under the MIT License.
By using, copying, modifying, or distributing this software you agree to the following:

---

### This Library is a Tool. Tools Are Neutral. Intent Is Not.

WinUtils contains functionality that overlaps with techniques used in:
- Windows optimization and system administration software
- Security research and penetration testing tools
- Anti-cheat and anti-tamper systems
- Malware, rootkits, and offensive security exploits

**The same code that lets an anti-cheat detect injected DLLs is the same code that injects them.**
**The same code that protects game assets with encryption is the same code used in ransomware.**

This is not a warning that the library is dangerous. It is a statement of fact about how this
class of software works. You are responsible for what you do with it.

---

### Authorized Use

You **MAY** use this library for:
- Software running on systems you personally own
- Security research on systems you have **written, explicit authorization** to test
- Penetration testing engagements with a signed scope-of-work agreement
- Anti-cheat systems for games or software you develop
- Windows optimization, system administration, or utility tools
- Educational purposes in isolated/lab environments
- Any lawful purpose on systems you are authorized to operate on

---

### Prohibited Use

You **MAY NOT** use this library for:
- Accessing, modifying, or monitoring systems you do not own and have not been authorized to test
- Creating malware, ransomware, spyware, or any software designed to harm, surveil, or extort
- Bypassing security controls on systems without explicit written authorization
- Any activity that violates the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act,
  the EU Directive on Attacks Against Information Systems, or equivalent laws in your jurisdiction
- Targeting individuals, organizations, or infrastructure without authorization

---

### Penetration Testers & Security Researchers

If you are a penetration tester or security researcher using this library:

- You are responsible for ensuring you have a valid, written scope-of-work or authorization document
  before using any `WinPower.hpp` or `WinKernel.hpp` functionality against a target system
- Functions like `Inject::InjectDLL`, `Token::StealFromProcess`, `Admin::BypassUACComHijack`,
  and `Memory::Write` are **inherently destructive** — use them only within your authorized scope
- Several functions in this library **will be flagged by antivirus and EDR products by design**.
  This is expected behavior. Do not attempt to use this library to evade detection on systems
  you are not authorized to test
- The author is not responsible for engagements that go out of scope, cause unintended damage,
  or result in legal action due to unauthorized use

---

### Malware Researchers & AV/EDR Developers

If you are developing defensive security tools, analyzing malware behavior, or building detection
signatures using this library as a reference:

- This library is intentionally documented so that the techniques are understood clearly
- Understanding offensive techniques is essential to building effective defenses
- Use of this library in a sandboxed or isolated analysis environment is encouraged
- The author supports the security research community and the responsible disclosure process

---

### No Warranty. No Liability.

This software is provided **"AS IS"** without warranty of any kind. The author:

- Makes no guarantees about fitness for any particular purpose
- Accepts **zero responsibility** for data loss, system damage, instability, BSODs,
  or any other outcome arising from use or misuse of this software
- Accepts **zero responsibility** for legal consequences resulting from misuse
- Accepts **zero responsibility** for antivirus detections, game bans, account suspensions,
  or any other consequence of using flagged techniques

**If you are unsure whether your intended use is legal or authorized — it probably isn't. Don't do it.**

---

### Reporting Misuse

If you discover this library being used maliciously or distributed as part of malware,
please report it. The goal of this project is to empower legitimate developers, researchers,
and system administrators — not to enable harm.

---

## Requirements

- Windows (Win32 API), C++17 or later
- MSVC, MinGW, or Clang-CL

### MSVC
```
/std:c++17 /DUNICODE /D_UNICODE
```

### MinGW / GCC
```bash
g++ -std=c++17 -DUNICODE -D_UNICODE yourfile.cpp \
    -luser32 -lshell32 -lwininet -lgdi32 -ladvapi32 \
    -lole32 -lcomdlg32 -ldwmapi -lbcrypt -lwbemuuid \
    -lws2_32 -liphlpapi -lpdh -lsetupapi -lpowrprof \
    -lwevtapi -ltaskschd
```

> `#pragma comment(lib, ...)` handles auto-linking on MSVC automatically.

---

## Compiler Notes

| Issue | Fix |
|-------|-----|
| `PROCESS_SYNCHRONIZE` undefined | Defined automatically in `WinPower.hpp` via `#ifndef` guard |
| `PROCESS_BASIC_INFORMATION` has no `Reserved3` | Fixed — reads by raw byte offset instead |
| `__try` requires at least one handler | Replaced with `OutputDebugString` timing trick (no `/EHa` needed) |
| `auto` cannot deduce type for `NtSetInformationThread` | Replaced `using T=` with explicit `typedef` |
| `IWbemLocator` has no member `Release` | Include `WinUtils.hpp` **before** `WinPower.hpp` — COM interfaces must be in global scope |
| DLL injection flagged by AV | Expected — detections are technique-based, not intent-based |
| Driver fails to load | Requires test signing mode: `bcdedit /set testsigning on` + reboot, or EV certificate |

### Required MSVC Flags
```
/std:c++17 /DUNICODE /D_UNICODE
```
For `WinPower.hpp` SEH functions you do **not** need `/EHa` — all `__try`/`__except` blocks have been replaced with portable equivalents.


---

## WinUtils.hpp — Namespace Reference

### Str:: / Dialog:: / File::
```cpp
Str::ToWide / ToNarrow / Format / Split / Trim / ReplaceAll

Dialog::Message / Error / Warning / YesNo / YesNoCancel
Dialog::OpenFile / SaveFile / BrowseFolder / InputBox

File::Create / CreateMany / ReadAll / WriteAll / Append
File::Delete / Copy / Move / Exists / Size
File::CreateDir / DeleteDir / ListDir
File::ExeDir / TempDir / TempFile
File::Watch(dir, callback, &running)
```

### Mouse:: / Keyboard:: / Clipboard::
```cpp
Mouse::GetPos / SetPos / MoveBy / Hide / Show
Mouse::LeftClick / RightClick / DoubleClick / Scroll / ClickAt
Mouse::SetCursorIcon / Confine / ReleaseConfinement / SmoothMove
Mouse::StartRecording / RecordFrame / StopRecording
Mouse::Replay / SaveRecording / LoadRecording

Keyboard::Press / KeyDown / KeyUp / TypeText / IsDown
Keyboard::Copy / Paste / Undo

Clipboard::GetText / SetText / Clear
```

### Process:: / Window::
```cpp
Process::OpenURL / OpenFile / Run / RunCapture
Process::Kill / CurrentPID / ListProcesses / IsRunning / Exit

Window::FindByTitle / FindByPartialTitle / FindAllByPartialTitle
Window::EnumAll / EnumByProcess / GetAtPoint
Window::Show / Minimize / Maximize / Restore / BringToFront
Window::Close / ForceDestroy / Send / Post
Window::IsMinimized / IsMaximized / IsVisible / IsAlive
Window::GetBounds / GetClientSize / GetPID
Window::FlashTaskbar / StopFlash
Window::SetBounds / CenterOnScreen
Window::SnapLeft / SnapRight / SnapTop / SnapBottom / SnapCorner / SnapFullscreen
Window::Tile / Cascade
Window::SetBorderless / SetClickThrough / SetToolWindow
Window::SetAlwaysOnTop / SetOpacity / SetDarkTitleBar
Window::SetRoundedCorners / SetAccentColor
Window::SetWndProc / RegisterShellHook
```

### System:: / Registry::
```cpp
System::GetUsername / GetComputerName / GetWindowsVersion
System::GetMemoryMB / GetCPUCount
System::Desktop / AppData / Documents / Downloads / System32
System::Sleep / Now / SetEnv / GetEnv / LockScreen / Power
System::IsAdmin / GetDrives / GetBatteryStatus / RelaunchAsAdmin

Registry::ReadString / WriteString / ReadDWORD / WriteDWORD
Registry::ReadQWORD / WriteQWORD / ReadBinary / WriteBinary / ReadMultiString
Registry::KeyExists / ValueExists / CreateKey / DeleteKeyRecursive
Registry::ListValues / ListSubkeys / ExportKey / ImportRegFile
Registry::AddToStartup / RemoveFromStartup
Registry::IsLightMode / SetLightMode / SetShowExtensions / SetShowHiddenFiles
Registry::RegisterFileAssociation / AddContextMenuEntry / RemoveContextMenuEntry
```

### Notify:: / Audio:: / Log:: / Hotkey:: / Screen:: / Net:: / Crypto:: / Ini::
```cpp
Notify::Balloon(title, text, timeoutMs)

Audio::Beep / SystemSound / Tone / PlayWAV / StopSound

Log::Logger("app.log").info("msg")  // DEBUG / INFO / WARN / ERROR

Hotkey::Register(MOD_CTRL | MOD_ALT, 'Q', callback)
Hotkey::RunLoop()

Screen::Capture / SaveBMP / GetPixelColor / GetPixelRGB / FindColor

Net::HttpGet / HttpPost / DownloadFile / GetLocalIP / IsConnected

Crypto::SHA256 / MD5 / XorObfuscate / Base64Encode / Base64Decode

Ini::Read / ReadInt / Write / WriteInt / DeleteKey / DeleteSection
```

### Console:: / Progress:: / Tray:: / Drive:: / FileAttr::
```cpp
Console::SetColor / ResetColor / Clear / SetTitle
Console::SetCursorPos / ShowCursor / SetSize / PrintColor / PrintRule

Progress::TaskbarProgress  .Set(%) / .SetIndeterminate / .SetError / .Clear

Tray::TrayIcon  .Init / .AddMenuItem / .AddSeparator / .OnLeftClick / .RunLoop

Drive::ListAll / GetType / GetFreeGB / GetTotalGB / GetLabel / SetLabel
Drive::GetFilesystem / IsReady / Eject / LockVolume / UnlockVolume

FileAttr::Hide / Unhide / IsHidden / SetReadOnly / SetSystem
FileAttr::HideAll / UnhideAll
FileAttr::WriteADS / ReadADS / DeleteADS  // NTFS Alternate Data Streams
```

### Encrypt:: — AES-256-CBC File Encryption
```cpp
Encrypt::EncryptData(bytes, "password")  // -> vector<BYTE>
Encrypt::DecryptData(bytes, "password")
Encrypt::EncryptString("secret", "password")  // -> base64 string
Encrypt::DecryptString(cipher, "password")
Encrypt::EncryptFile("config.dat", "password")        // -> config.dat.enc
Encrypt::DecryptFile("config.dat.enc", "password")
Encrypt::EncryptDirectory("assets/", "password", ".dat")
Encrypt::DecryptDirectory("assets/", "password")
Encrypt::GeneratePassword(32)   // cryptographically random
Encrypt::SecureDelete(path)     // 3-pass wipe then delete
```

---

## WinHardware.hpp — Namespace Reference

```cpp
CPU::GetInfo / GetName / GetCoreCount / GetLogicalCount / GetMaxClockMHz
CPU::GetUsagePercent()          // live %, ~100ms PDH sample
CPU::GetPerCoreUsage()          // -> vector<double>
CPU::GetTemperatureCelsius()    // ACPI thermal zones, requires Admin

GPU::GetAll / GetName / GetVRAM_GB / GetCurrentMode

RAM::GetSticks / GetTotalGB / GetAvailableGB / GetUsagePercent
RAM::GetTypeString / GetSpeedMHz

Disk::GetAll / GetPartitions / GetReadWriteSpeed(diskIndex)

Monitor::GetAll / GetPrimaryResolution / GetPrimaryRefreshHz
Monitor::GetDPI / GetScaleFactor / GetVirtualDesktopSize

NetInfo::GetAll              // full adapter info: IPv4/6, MAC, DNS, gateway, speed
NetInfo::GetThroughput / Ping

Devices::GetUSBDevices / GetPrinters / GetAllPnPDeviceNames

Battery::GetInfo / GetPercent / IsCharging / HasBattery

Software::GetInstalled / IsInstalled("Steam")

ProcessInfo::GetAll / GetByPID / GetTopByRAM(10)

Sensors::GetThermalZones / GetUptimeSeconds / GetUptimeString / GetPageFileUsageMB

Board::GetBIOS / GetMotherboard / GetWindowsSerial / GetMachineUUID
```

---

## WinExtra.hpp — Namespace Reference

```cpp
Mutex::EnforceSingleInstance / IsRunning / Create / Release

Pipe::CreateServer / WaitForClient / Connect / Send / Receive / Close / QuickSend

EventLog::Write / Read / Clear

Firewall::AllowProgram / AllowPort / RemoveRule / SetEnabled  // requires Admin

Scheduler::CreateStartupTask / DeleteTask / TaskExists  // requires Admin

Theme::IsDarkMode / SetDarkMode / GetAccentColor / GetWallpaper / SetWallpaper
Theme::GetSystemDPI / GetCurrentTheme / IsTransparencyEnabled / SetTransparencyEnabled

PowerMgmt::PreventSleep / AllowSleep / Sleep / Hibernate
PowerMgmt::GetPowerPlans / SetHighPerformance / SetBalanced / SetPowerSaver
PowerMgmt::GetActivePlanName / IsPluggedIn

NetConfig::GetHostname / FlushDNS / RenewDHCP
NetConfig::ResetTCPIP / ResetWinsock  // requires Admin
NetConfig::IsPortOpen / GetPublicIP
```

---

## WinPower.hpp — Namespace Reference

```cpp
// Ownership (!! dangerous on system files !!)
Ownership::EnableOwnershipPrivileges
Ownership::TakeOwnershipFile / GrantFullControlFile / UnlockFileForEveryone
Ownership::GetFileOwner / CanRead / CanWrite
Ownership::TakeOwnershipKey / GrantFullControlKey
Ownership::ListPrivileges / EnablePrivilege / DisablePrivilege / HasPrivilege
Ownership::GetIntegrityLevelStr / IsElevated

// Admin & UAC
Admin::IsRunningAsAdmin / ForceRunAsAdmin / RelaunchElevated / RunElevated
Admin::DisableUAC / EnableUAC / SetUACLevel / BypassUACComHijack
Admin::SetRequireAdminFlag / ClearRequireAdminFlag

// Services
Service::Exists / GetState / Start / Stop / Pause / Resume
Service::Install / Uninstall / SetStartType / InstallAndStart / ListAll

// Process Control
ProcessCtrl::Suspend / Resume
ProcessCtrl::CreateSuspended / GetEntryPoint / WaitAndGetExitCode
ProcessCtrl::SetPriority / SetAffinity

// Token Manipulation
Token::StealFromProcess / StealFromProcessName
Token::Impersonate / RevertImpersonation
Token::CreateProcessWithToken / GetTokenUsername / IsSystemToken

// Memory
Memory::Read / Write / ReadT / WriteT
Memory::ReadString / ReadWString / WriteString
Memory::Alloc / Free / Protect
Memory::EnumerateRegions / FindPattern / FindPatternAll
Memory::DumpRegion / GetModuleBase / ListModules

// Anti-Debug
AntiDebug::IsDebuggerPresent / IsRemoteDebugger / CheckHeapFlags
AntiDebug::CheckNtGlobalFlag / CheckHardwareBreakpoints
AntiDebug::CheckParentProcess / CheckExceptionHandler
AntiDebug::AnyDebuggerDetected / HideFromDebugger / BlockDebuggerAttach
AntiDebug::TriggerIfDebugged(onDebug, otherwise)

// Injection (!! AV flagged — research/personal use only !!)
Inject::InjectDLL / EjectDLL / HijackThread / RemoteExecute

// WMI Quick Queries
WMI::Query / GetCPUName / GetGPUName / GetBIOSVersion
WMI::GetWindowsSerial / GetTotalRAM_GB / GetDiskDrives / GetMotherboard / GetMACAddresses
```

---

## WinKernel.hpp — Namespace Reference

Requires `WinUtils.hpp` + `WinPower.hpp`.

> **Driver signing:** unsigned `.sys` files require test signing mode (`bcdedit /set testsigning on` + reboot) or an EV code-signing certificate. Secure Boot must be disabled for test mode.

```cpp
// Kernel Driver Interface
Driver::Load(name, sysPath) / Unload(name) / IsLoaded(name)
Driver::Open(devicePath)    // -> HANDLE to device object
Driver::SendIOCTL(handle, code, inBuf, inSz, outBuf, outSz)
Driver::SendIOCTL<TIn,TOut>(handle, code, input, output)  // typed

// RAII driver handle
WinUtils::Driver::DriverHandle drv("\\\\.\\MyDriver");
drv.IOCTL(IOCTL_CODE, inputStruct, outputStruct);

// Anti-Cheat
AntiCheat::ScanModules(whitelist)           // returns suspicious DLL names
AntiCheat::CheckSelfIntegrity(expectedHash)
AntiCheat::GetSelfHash()
AntiCheat::WatchMemoryRegion(addr, size, onTamper, &running)

AntiCheat::SpeedHackDetector detector;
detector.Check(gameDeltaSeconds)            // -> bool

AntiCheat::DetectOverlays()                 // known overlay processes
AntiCheat::DetectTransparentOverlay()       // layered window detection
AntiCheat::IsRunningInVM()                  // CPUID hypervisor bit + vendor string
AntiCheat::DetectVMRegistry()
AntiCheat::DetectVMProcesses()
AntiCheat::IsVirtualEnvironment()           // all three combined
AntiCheat::DetectSingleStep()
AntiCheat::DetectTimeManipulation()

auto result = AntiCheat::RunFullScan(moduleWhitelist, expectedHash);
AntiCheat::IsCheating(result)               // -> bool
// result.debuggerDetected / vmDetected / overlayDetected
// result.integrityFailed / timingAnomalies
// result.suspiciousModules / overlayProcesses
```

---

## Anti-Cheat Architecture

For a production anti-cheat the typical layered approach using this library:

**Asset protection**
```cpp
// On install — encrypt assets with a machine-specific key
std::string machineKey = WinUtils::Board::GetMachineUUID();
WinUtils::Encrypt::EncryptDirectory("assets/", machineKey, ".pak");

// At runtime — decrypt to RAM only, never write decrypted files to disk
std::ifstream f("assets/data.pak.enc", std::ios::binary);
std::vector<BYTE> enc(std::istreambuf_iterator<char>(f), {});
auto dec = WinUtils::Encrypt::DecryptData(enc, machineKey);
```

**Runtime checks**
```cpp
// Full scan on startup and periodically
auto result = WinUtils::AntiCheat::RunFullScan(moduleWhitelist, selfHash);
if (WinUtils::AntiCheat::IsCheating(result)) { /* handle */ }

// Watch critical memory regions for tampering
bool watching = true;
std::thread([]{ WinUtils::AntiCheat::WatchMemoryRegion(
    &gameHealth, sizeof(int),
    []{ /* tamper detected */ },
    &watching); }).detach();
```

**Kernel driver IPC**
```cpp
WinUtils::Driver::DriverHandle drv("\\\\.\\MyAntiCheat");
if (drv.IsValid()) {
    ScanRequest req{ GetCurrentProcessId() };
    ScanResponse resp{};
    drv.IOCTL(IOCTL_SCAN_PROCESS, req, resp);
}
```

---

## Notes

- Boot sector / MBR / VBR manipulation is intentionally not included.
- `Inject::` and `AntiDebug::` exist for security research, game development, and anti-cheat. Using them against systems you do not own is illegal.
- Functions operating on system files/registry can make Windows unbootable. Back up before modifying `C:\Windows` or `HKLM\SYSTEM`.
- Several `WinPower.hpp` and `WinKernel.hpp` functions will be flagged by AV/EDR. Detections are based on technique, not intent.

---

## License

MIT License — Copyright (c) 2026 RedMeansWar

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---
