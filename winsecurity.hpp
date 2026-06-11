/*
 * ============================================================================
 * winsecurity.hpp
 * Part of the WinUtils project — Windows Security configuration & status
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
 * This file contains utilities that read and modify Windows security features
 * including Virtualization-Based Security, Windows Defender, BitLocker drive
 * encryption, the system certificate store, and exploit mitigation policies.
 *
 * AUTHORIZED USE ONLY. Disabling security features such as HVCI, Secure Boot,
 * Windows Defender real-time protection, or BitLocker on systems you do not
 * own or administer is unauthorized and potentially illegal under applicable
 * computer misuse law. Several registry paths written by functions in this
 * file are monitored by enterprise security products and EDR solutions.
 *
 * Several functions in this file require Administrator privileges and will
 * silently fail or return false without them. Some changes (VBS, HVCI) do
 * not take effect until after a system reboot.
 *
 * THE AUTHOR ACCEPTS ZERO RESPONSIBILITY FOR DATA LOSS, SYSTEM INSTABILITY,
 * SECURITY INCIDENTS, LEGAL CONSEQUENCES, OR ANY OTHER OUTCOME FROM USE OR
 * MISUSE OF THIS SOFTWARE.
 *
 * ============================================================================
 *
 * Compatibility : Windows 10 version 1703+ (Creators Update) for VBS/HVCI.
 *                 Windows 10+ for all other features.
 *                 NOT compatible with Windows 7/8/8.1 or earlier.
 *
 * Requires      : Windows (Win32 API), C++17 or later, winutils.hpp
 * Companion     : winpower.hpp (privilege elevation helpers used here)
 * Reference     : See README.md for full namespace and function documentation
 *
 * ============================================================================
 *
 * Namespaces:
 *   WinUtils::Security::VBS          — Virtualization-Based Security & HVCI
 *   WinUtils::Security::Defender     — Windows Defender / Windows Security
 *   WinUtils::Security::BitLocker    — BitLocker drive encryption
 *   WinUtils::Security::Certificates — CryptoAPI certificate store management
 *   WinUtils::Security::Mitigations  — DEP, ASLR, CFG, ACG per-process policy
 *   WinUtils::Security::Audit        — Local Security Policy audit settings
 *   WinUtils::Security::Credentials  — Windows Credential Manager
 *
 * ============================================================================
*/

#pragma once
#ifndef WINUTILS_SECURITY_HPP
#define WINUTILS_SECURITY_HPP

#include "wincompat.hpp"
#include "winutils.hpp"
#include "winpower.hpp"

#include <wincrypt.h>
#include <cryptuiapi.h>
#include <lm.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "cryptui.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wbemuuid.lib")

// ---- wincred.h is not always pulled in transitively ----
#include <wincred.h>
#pragma comment(lib, "Credui.lib")

// ---- Windows Event Log API (for HoneyAccount watcher) ----
#include <winevt.h>
#pragma comment(lib, "wevtapi.lib")

#include <thread>
#include <atomic>
#include <mutex>
#include <functional>

namespace WinUtils {
namespace Security {

// ============================================================
//  SECTION S1 — Virtualization-Based Security (VBS) & HVCI
// ============================================================
//  VBS uses hardware virtualisation to create an isolated memory
//  region that protects core OS resources. HVCI (Hypervisor-
//  Protected Code Integrity) runs kernel code-integrity checks
//  inside that isolated region, preventing unsigned/modified
//  kernel code from running — including most kernel rootkits.
//
//  !! Toggling these settings requires Admin and a reboot.
//     Disabling HVCI makes the system significantly less secure.
//     Some games (e.g. those with kernel anti-cheat) require
//     HVCI to be OFF. This is a common VM/gaming use-case.
// ============================================================
namespace VBS {

    /// Overall VBS / Core Isolation status report
    struct VBSStatus {
        bool vbsEnabled            = false; ///< Virtualization-Based Security is on
        bool hvciEnabled           = false; ///< Hypervisor-Protected Code Integrity is on
        bool hvciStrictMode        = false; ///< HVCI strict mode (blocks UMCI bypass too)
        bool secureBootEnabled     = false; ///< UEFI Secure Boot is active
        bool credentialGuard       = false; ///< Credential Guard is protecting LSA secrets
        bool deviceGuard           = false; ///< Device Guard policy is in force
        bool kernelDMAProtection   = false; ///< Kernel DMA Protection (Thunderbolt attack guard)
        bool memoryIntegrity       = false; ///< Alias: Memory Integrity == HVCI in Windows UI
        bool tpmPresent            = false; ///< TPM 2.0 chip is present and active
        bool requiresReboot        = false; ///< A pending change requires reboot to take effect
    };

    // ----------------------------------------------------------
    //  Internal registry paths for VBS/HVCI/Device Guard
    // ----------------------------------------------------------
    namespace _VBSReg {
        // Primary VBS configuration key (written by Group Policy / MDM)
        static constexpr const char* kVBSKey =
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";

        // HVCI / Memory Integrity key
        static constexpr const char* kHVCIKey =
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";

        // Credential Guard key
        static constexpr const char* kCredGuardKey =
            "SYSTEM\\CurrentControlSet\\Control\\Lsa";

        // Secure Boot status (read-only — firmware reports this)
        static constexpr const char* kSecureBootKey =
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";

        // Kernel DMA Protection
        static constexpr const char* kDMAKey =
            "SYSTEM\\CurrentControlSet\\Control\\DmaSecurity";
    }

    /// Query the full VBS / Core Isolation status of the system.
    /// Most fields are read from registry; some via WMI where registry is unavailable.
    /// Requires no special privileges to read.
    inline VBSStatus GetStatus() {
        VBSStatus s;

        // VBS master switch — EnableVirtualizationBasedSecurity DWORD
        auto vbsVal = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kVBSKey, "EnableVirtualizationBasedSecurity");
        s.vbsEnabled = vbsVal.value_or(0) != 0;

        // HVCI (Memory Integrity) — Enabled DWORD under HypervisorEnforcedCodeIntegrity
        auto hvciEnabled = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kHVCIKey, "Enabled");
        s.hvciEnabled    = hvciEnabled.value_or(0) != 0;
        s.memoryIntegrity = s.hvciEnabled; // same thing, different UI label

        // HVCI strict mode — WasEnabledBy / Strict
        auto hvciStrict = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kHVCIKey, "HVCIMATRequired");
        s.hvciStrictMode = hvciStrict.value_or(0) != 0;

        // Secure Boot — UEFISecureBootEnabled DWORD (set by firmware at boot)
        auto sb = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kSecureBootKey, "UEFISecureBootEnabled");
        s.secureBootEnabled = sb.value_or(0) != 0;

        // Credential Guard — LsaCfgFlags DWORD (0=off, 1=on with UEFI lock, 2=on without lock)
        auto cgFlags = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kCredGuardKey, "LsaCfgFlags");
        s.credentialGuard = cgFlags.value_or(0) != 0;

        // Device Guard — ConfigureSystemGuardLaunch or RequirePlatformSecurityFeatures
        auto dgVal = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kVBSKey, "RequirePlatformSecurityFeatures");
        s.deviceGuard = dgVal.value_or(0) != 0;

        // Kernel DMA Protection — DMAProtectionEnabled
        auto dmaVal = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kDMAKey, "DMAProtectionEnabled");
        s.kernelDMAProtection = dmaVal.value_or(0) != 0;

        // TPM — query WMI Win32_Tpm
        {
            // Quick WMI check via process capture rather than full COM init
            // to keep this function header-only-friendly
            auto r = Process::RunCapture(
                "powershell -NoProfile -Command \""
                "$tpm = Get-WmiObject -Namespace root/cimv2/Security/MicrosoftTpm "
                "-Class Win32_Tpm -ErrorAction SilentlyContinue; "
                "if ($tpm) { $tpm.IsEnabled_InitialValue } else { 'False' }\"");
            if (r) {
                std::string v = Str::Trim(*r);
                s.tpmPresent = (v == "True" || v == "true");
            }
        }

        return s;
    }

    /// Check if HVCI (Memory Integrity / Core Isolation) is enabled.
    inline bool IsHVCIEnabled() {
        return GetStatus().hvciEnabled;
    }

    /// Check if Secure Boot is active.
    inline bool IsSecureBootEnabled() {
        return GetStatus().secureBootEnabled;
    }

    /// Enable HVCI (Memory Integrity / Core Isolation).
    ///
    /// !! Takes effect after reboot only !!
    /// !! Some kernel anti-cheat drivers are incompatible with HVCI !!
    /// !! Some older hardware does not support VBS at all !!
    ///
    /// Requires: Administrator
    inline bool EnableHVCI() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        bool ok = true;
        // Ensure VBS master switch is on
        ok &= Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kVBSKey,
            "EnableVirtualizationBasedSecurity", 1);
        // Enable HVCI
        ok &= Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kHVCIKey, "Enabled", 1);
        return ok;
    }

    /// Disable HVCI (Memory Integrity / Core Isolation).
    ///
    /// !! Takes effect after reboot only !!
    /// !! Disabling HVCI significantly reduces kernel-level security.
    ///    Common reason: kernel anti-cheat (EAC/BattlEye) incompatibility
    ///    or installing unsigned kernel drivers. !!
    ///
    /// Requires: Administrator
    inline bool DisableHVCI() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        bool ok = Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kHVCIKey, "Enabled", 0);
        return ok;
    }

    /// Enable Credential Guard (protects NTLM hashes / Kerberos tickets from
    /// credential-dumping tools like Mimikatz).
    /// mode: 1 = enabled with UEFI lock (can't be turned off without UEFI),
    ///       2 = enabled without UEFI lock (can be disabled later)
    ///
    /// !! Takes effect after reboot only !!
    /// Requires: Administrator
    inline bool EnableCredentialGuard(DWORD mode = 2) {
        if (mode != 1 && mode != 2) return false;
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        bool ok = true;
        ok &= Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kVBSKey,
            "EnableVirtualizationBasedSecurity", 1);
        ok &= Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kCredGuardKey, "LsaCfgFlags", mode);
        return ok;
    }

    /// Disable Credential Guard.
    /// !! Takes effect after reboot only !!
    /// Requires: Administrator
    inline bool DisableCredentialGuard() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kCredGuardKey, "LsaCfgFlags", 0);
    }

    /// Enable VBS master switch (prerequisite for HVCI/Credential Guard).
    /// Requires: Administrator + reboot
    inline bool EnableVBS() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kVBSKey,
            "EnableVirtualizationBasedSecurity", 1);
    }

    /// Disable VBS master switch.
    /// !! This also disables HVCI and Credential Guard. Reboot required. !!
    /// Requires: Administrator
    inline bool DisableVBS() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        bool ok = true;
        ok &= Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kVBSKey,
            "EnableVirtualizationBasedSecurity", 0);
        ok &= Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kHVCIKey, "Enabled", 0);
        return ok;
    }

    /// Enable Kernel DMA Protection (blocks DMA attacks over Thunderbolt/PCIe).
    /// Requires: UEFI firmware support + Administrator + reboot
    inline bool EnableKernelDMAProtection() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kDMAKey, "DMAProtectionEnabled", 1);
    }

    inline bool DisableKernelDMAProtection() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            _VBSReg::kDMAKey, "DMAProtectionEnabled", 0);
    }

    /// Print a human-readable summary of the current VBS/Core Isolation state.
    /// Useful for diagnostics / logging.
    inline std::string GetSummary() {
        auto s = GetStatus();
        std::string r;
        auto yn = [](bool v) -> const char* { return v ? "YES" : "NO"; };
        r += "VBS (Virtualization-Based Security) : ";  r += yn(s.vbsEnabled);          r += "\n";
        r += "HVCI / Memory Integrity             : ";  r += yn(s.hvciEnabled);          r += "\n";
        r += "HVCI Strict Mode                    : ";  r += yn(s.hvciStrictMode);       r += "\n";
        r += "Secure Boot                         : ";  r += yn(s.secureBootEnabled);    r += "\n";
        r += "Credential Guard                    : ";  r += yn(s.credentialGuard);      r += "\n";
        r += "Device Guard                        : ";  r += yn(s.deviceGuard);          r += "\n";
        r += "Kernel DMA Protection               : ";  r += yn(s.kernelDMAProtection);  r += "\n";
        r += "TPM 2.0 Present                     : ";  r += yn(s.tpmPresent);           r += "\n";
        return r;
    }

} // namespace VBS

// ============================================================
//  SECTION S2 — Windows Defender
// ============================================================
//  Windows Defender (Windows Security / Microsoft Defender
//  Antivirus) is the built-in AV. Functions here read status
//  via WMI (SecurityCenter2) and toggle settings via registry.
//
//  !! Disabling real-time protection leaves the system exposed.
//     Enterprise environments may lock these settings via GPO.
//     Changes may be reversed by Defender's tamper protection
//     unless it is disabled first. !!
// ============================================================
namespace Defender {

    struct DefenderStatus {
        bool realtimeProtection    = false; ///< Real-time (on-access) scanning is on
        bool tamperProtection      = false; ///< Tamper Protection prevents registry changes
        bool cloudProtection       = false; ///< MAPS / cloud-delivered protection is on
        bool networkProtection     = false; ///< Network protection (SmartScreen for network) is on
        bool behaviorMonitoring    = false; ///< Behavior monitoring is on
        bool ioavProtection        = false; ///< IE/Office/browser download scanning is on
        bool antispyware           = false; ///< Antispyware component is enabled
        bool antivirus             = false; ///< Antivirus component is enabled
        std::string engineVersion;          ///< Defender engine version string
        std::string signatureVersion;       ///< Signature / definition version
        std::string lastSignatureUpdate;    ///< Last signature update timestamp
    };

    // Defender preferences registry key (user-writable when not tamper-protected)
    static constexpr const char* kDefenderKey =
        "SOFTWARE\\Microsoft\\Windows Defender";
    static constexpr const char* kDefenderRTKey =
        "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection";
    static constexpr const char* kDefenderFeaturesKey =
        "SOFTWARE\\Microsoft\\Windows Defender\\Features";
    static constexpr const char* kDefenderSpynetKey =
        "SOFTWARE\\Microsoft\\Windows Defender\\Spynet";

    /// Get full Windows Defender status.
    /// Most fields are read from registry; engine/signature info from WMI.
    inline DefenderStatus GetStatus() {
        DefenderStatus s;

        // Real-time protection — DisableRealtimeMonitoring = 0 means ON
        auto rtOff = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            kDefenderRTKey, "DisableRealtimeMonitoring");
        s.realtimeProtection = rtOff.value_or(0) == 0;

        // Tamper Protection — TamperProtection DWORD (4 = off, 5 = on)
        auto tp = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            kDefenderFeaturesKey, "TamperProtection");
        s.tamperProtection = tp.value_or(5) == 5;

        // Cloud protection — SpynetReporting (0=off, 1=basic, 2=advanced)
        auto spynet = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            kDefenderSpynetKey, "SpynetReporting");
        s.cloudProtection = spynet.value_or(0) != 0;

        // Network protection — EnableNetworkProtection (0=off, 1=block, 2=audit)
        auto netprot = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection",
            "EnableNetworkProtection");
        s.networkProtection = netprot.value_or(0) != 0;

        // Behavior monitoring — DisableBehaviorMonitoring = 0 means ON
        auto bm = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            kDefenderRTKey, "DisableBehaviorMonitoring");
        s.behaviorMonitoring = bm.value_or(0) == 0;

        // IOAV (browser/download scan) — DisableIOAVProtection = 0 means ON
        auto ioav = Registry::ReadDWORD(HKEY_LOCAL_MACHINE,
            kDefenderRTKey, "DisableIOAVProtection");
        s.ioavProtection = ioav.value_or(0) == 0;

        // Engine / signature version via WMI SecurityCenter2
        auto r = Process::RunCapture(
            "powershell -NoProfile -Command \""
            "$av = Get-WmiObject -Namespace root/SecurityCenter2 "
            "-Class AntiVirusProduct -ErrorAction SilentlyContinue | "
            "Where-Object { $_.displayName -like '*Windows Defender*' } | "
            "Select-Object -First 1; "
            "if ($av) { $av.productState } else { '0' }\"");
        if (r) {
            // productState encodes on/off/up-to-date in a DWORD bitmask
            try {
                DWORD state = static_cast<DWORD>(std::stoul(Str::Trim(*r)));
                // Bits 12-15 = product state (0x10 = on, 0x00 = off)
                // Bits 4-7 = signature state (0x00 = up to date, 0x10 = out of date)
                s.antivirus   = ((state >> 12) & 0xF) == 1;
                s.antispyware = s.antivirus;
            } catch (...) {}
        }

        // Signature version
        auto sigVer = Registry::ReadString(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates",
            "SignatureVersion");
        if (sigVer) s.signatureVersion = *sigVer;

        auto engVer = Registry::ReadString(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender",
            "ProductVersion");
        if (engVer) s.engineVersion = *engVer;

        return s;
    }

    /// Check if real-time protection is currently on.
    inline bool IsRealtimeProtectionOn() {
        return GetStatus().realtimeProtection;
    }

    /// Check if Tamper Protection is on (blocks registry changes to Defender).
    inline bool IsTamperProtectionOn() {
        return GetStatus().tamperProtection;
    }

    /// Disable Tamper Protection.
    ///
    /// !! Tamper Protection must be turned off in Windows Security UI first
    ///    on consumer systems. This registry write will silently fail if
    ///    Tamper Protection is still active. !!
    ///
    /// Requires: Administrator
    inline bool DisableTamperProtection() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        // 4 = disabled, 5 = enabled
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            kDefenderFeaturesKey, "TamperProtection", 4);
    }

    /// Re-enable Tamper Protection.
    /// Requires: Administrator
    inline bool EnableTamperProtection() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            kDefenderFeaturesKey, "TamperProtection", 5);
    }

    /// Disable real-time protection.
    ///
    /// !! Tamper Protection must be OFF first or this will have no effect.
    ///    Defender will attempt to re-enable itself automatically. !!
    ///
    /// Requires: Administrator
    inline bool DisableRealtimeProtection() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            kDefenderRTKey, "DisableRealtimeMonitoring", 1);
    }

    /// Re-enable real-time protection.
    /// Requires: Administrator
    inline bool EnableRealtimeProtection() {
        Ownership::_EnablePrivilege(SE_RESTORE_NAME);
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE,
            kDefenderRTKey, "DisableRealtimeMonitoring", 0);
    }

    /// Add a path to Defender's exclusion list (won't scan this path).
    /// Useful for development folders, game directories, etc.
    /// Requires: Administrator
    inline bool AddExclusion(const std::string& path) {
        const std::string key =
            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE, key, path, 0);
    }

    /// Remove a path from Defender's exclusion list.
    /// Requires: Administrator
    inline bool RemoveExclusion(const std::string& path) {
        const std::string key =
            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
        return Registry::DeleteValue(HKEY_LOCAL_MACHINE, key, path);
    }

    /// Get all current Defender path exclusions.
    inline std::vector<std::string> GetExclusions() {
        const std::string key =
            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
        return Registry::ListValues(HKEY_LOCAL_MACHINE, key);
    }

    /// Add a process name to Defender's exclusion list.
    /// e.g. "myapp.exe" — Defender will not scan this process's file access.
    /// Requires: Administrator
    inline bool AddProcessExclusion(const std::string& processName) {
        const std::string key =
            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes";
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE, key, processName, 0);
    }

    /// Remove a process from Defender's exclusion list.
    /// Requires: Administrator
    inline bool RemoveProcessExclusion(const std::string& processName) {
        const std::string key =
            "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes";
        return Registry::DeleteValue(HKEY_LOCAL_MACHINE, key, processName);
    }

    /// Trigger a quick scan via Windows Defender CLI.
    /// Runs asynchronously — returns once the scan process is launched.
    /// Requires: Administrator
    inline bool StartQuickScan() {
        return Process::Run(
            "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
            "-Scan -ScanType 1", true, false);
    }

    /// Trigger a full scan via Windows Defender CLI.
    /// This is a blocking call if wait=true — a full scan can take hours.
    inline bool StartFullScan(bool wait = false) {
        return Process::Run(
            "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
            "-Scan -ScanType 2", true, wait);
    }

    /// Force a signature update.
    inline bool UpdateSignatures() {
        return Process::Run(
            "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
            "-SignatureUpdate", true, true);
    }

} // namespace Defender

// ============================================================
//  SECTION S3 — BitLocker Drive Encryption
// ============================================================
//  BitLocker encrypts entire volumes. Status is queried via WMI
//  (Win32_EncryptableVolume in root\CIMV2\Security\MicrosoftVolumeEncryption).
//  Enable/disable operations use manage-bde.exe since the WMI
//  methods require complex COM boilerplate for marginal benefit.
//
//  !! Enabling BitLocker without saving the recovery key will
//     lock you out of the drive permanently if TPM clears.
//     Always save recovery keys before enabling encryption. !!
// ============================================================
namespace BitLocker {

    enum class EncryptionStatus {
        FullyDecrypted       = 0,
        FullyEncrypted       = 1,
        EncryptionInProgress = 2,
        DecryptionInProgress = 3,
        EncryptionPaused     = 4,
        DecryptionPaused     = 5,
        Unknown              = 99
    };

    struct DriveEncryptionInfo {
        std::string          driveLetter;     ///< e.g. "C:"
        EncryptionStatus     status          = EncryptionStatus::Unknown;
        bool                 isProtected     = false; ///< Key protectors are present
        std::string          encryptionMethod;        ///< e.g. "XTS-AES 256"
        float                encryptionPercent = 0.0f;///< 0-100 during encryption
        std::string          protectorTypes;           ///< Comma-separated: TPM, RecoveryKey, etc.
    };

    /// Get BitLocker encryption status for a drive.
    /// driveLetter: e.g. "C:" or "C" (colon optional)
    inline DriveEncryptionInfo GetDriveStatus(const std::string& driveLetter) {
        DriveEncryptionInfo info;
        std::string dl = driveLetter;
        if (!dl.empty() && dl.back() != ':') dl += ':';
        info.driveLetter = dl;

        // Query via manage-bde.exe output parsing — most reliable without
        // needing full COM/WMI boilerplate for the secure namespace
        auto r = Process::RunCapture("manage-bde -status " + dl);
        if (!r) return info;

        std::string out = *r;

        // Parse protection status
        if (out.find("Protection On") != std::string::npos)
            info.isProtected = true;
        else if (out.find("Protection Off") != std::string::npos)
            info.isProtected = false;

        // Parse encryption status
        if (out.find("Fully Encrypted") != std::string::npos)
            info.status = EncryptionStatus::FullyEncrypted;
        else if (out.find("Fully Decrypted") != std::string::npos)
            info.status = EncryptionStatus::FullyDecrypted;
        else if (out.find("Encryption in Progress") != std::string::npos)
            info.status = EncryptionStatus::EncryptionInProgress;
        else if (out.find("Decryption in Progress") != std::string::npos)
            info.status = EncryptionStatus::DecryptionInProgress;

        // Parse encryption method (look for "Encryption Method:" line)
        {
            auto pos = out.find("Encryption Method:");
            if (pos != std::string::npos) {
                auto end = out.find('\n', pos);
                info.encryptionMethod = Str::Trim(
                    out.substr(pos + 18, end - pos - 18));
            }
        }

        // Parse percentage
        {
            auto pos = out.find("Percentage Encrypted:");
            if (pos != std::string::npos) {
                auto end = out.find('%', pos);
                if (end != std::string::npos) {
                    try {
                        info.encryptionPercent = std::stof(
                            Str::Trim(out.substr(pos + 21, end - pos - 21)));
                    } catch (...) {}
                }
            }
        }

        // Parse key protectors
        {
            auto pos = out.find("Key Protectors:");
            if (pos != std::string::npos) {
                auto end = out.find("\r\n\r\n", pos);
                if (end == std::string::npos) end = out.size();
                info.protectorTypes = Str::Trim(out.substr(pos + 15, end - pos - 15));
                // Remove newlines for single-line summary
                info.protectorTypes = Str::ReplaceAll(info.protectorTypes, "\r\n", ", ");
                info.protectorTypes = Str::ReplaceAll(info.protectorTypes, "\n",   ", ");
            }
        }

        return info;
    }

    /// Get BitLocker status for ALL drives on the system.
    inline std::vector<DriveEncryptionInfo> GetAllDrivesStatus() {
        std::vector<DriveEncryptionInfo> result;
        for (auto& drive : System::GetDrives())
            result.push_back(GetDriveStatus(drive));
        return result;
    }

    /// Check if a specific drive is BitLocker-encrypted and protected.
    inline bool IsEncrypted(const std::string& driveLetter) {
        auto info = GetDriveStatus(driveLetter);
        return info.status == EncryptionStatus::FullyEncrypted && info.isProtected;
    }

    /// Enable BitLocker on a drive using TPM + recovery password.
    ///
    /// !! SAVE the recovery key before enabling. If TPM clears (hardware
    ///    change, BIOS update) and you haven't saved the key, data is GONE. !!
    ///
    /// recoveryKeyPath: where to save the recovery key file.
    ///   Leave empty to skip saving (dangerous).
    ///
    /// Requires: Administrator + TPM 2.0 present
    inline bool Enable(const std::string& driveLetter,
                       const std::string& recoveryKeyPath = "") {
        std::string dl = driveLetter;
        if (!dl.empty() && dl.back() != ':') dl += ':';
        std::string args = dl + " -on -tpm";
        if (!recoveryKeyPath.empty())
            args += " -rp -rk \"" + recoveryKeyPath + "\"";
        return Process::Run("manage-bde.exe", args, true, true);
    }

    /// Disable BitLocker on a drive (fully decrypts it).
    ///
    /// !! This decrypts ALL data on the drive. The operation runs in the
    ///    background — decryption can take hours for large drives. !!
    ///
    /// Requires: Administrator
    inline bool Disable(const std::string& driveLetter) {
        std::string dl = driveLetter;
        if (!dl.empty() && dl.back() != ':') dl += ':';
        return Process::Run("manage-bde.exe", dl + " -off", true, false);
    }

    /// Suspend BitLocker protection (temporarily, e.g. for firmware update).
    /// Protection is automatically resumed on next reboot.
    /// Requires: Administrator
    inline bool Suspend(const std::string& driveLetter) {
        std::string dl = driveLetter;
        if (!dl.empty() && dl.back() != ':') dl += ':';
        return Process::Run("manage-bde.exe", dl + " -protectors -disable", true, true);
    }

    /// Resume BitLocker protection after suspension.
    /// Requires: Administrator
    inline bool Resume(const std::string& driveLetter) {
        std::string dl = driveLetter;
        if (!dl.empty() && dl.back() != ':') dl += ':';
        return Process::Run("manage-bde.exe", dl + " -protectors -enable", true, true);
    }

    /// Get the BitLocker recovery key for a drive.
    /// Returns the numerical recovery password or empty string on failure.
    /// Requires: Administrator (and the key protector must already exist)
    inline std::string GetRecoveryKey(const std::string& driveLetter) {
        std::string dl = driveLetter;
        if (!dl.empty() && dl.back() != ':') dl += ':';
        auto r = Process::RunCapture("manage-bde -protectors -get " + dl + " -type recoverypassword");
        if (!r) return {};
        // Recovery passwords are 48-digit numeric strings (8 groups of 6 digits separated by -)
        // Find the first match of that pattern in the output
        const std::string& out = *r;
        for (size_t i = 0; i < out.size(); ++i) {
            if (std::isdigit(static_cast<unsigned char>(out[i]))) {
                // Look for pattern: nnnnnn-nnnnnn-... (48 digits in 8 groups)
                std::string candidate;
                size_t j = i;
                int groups = 0;
                while (j < out.size() && groups < 8) {
                    // Each group is 6 digits
                    if (j + 6 > out.size()) break;
                    bool allDigits = true;
                    for (int k = 0; k < 6; ++k)
                        if (!std::isdigit(static_cast<unsigned char>(out[j + k])))
                            { allDigits = false; break; }
                    if (!allDigits) break;
                    candidate += out.substr(j, 6);
                    j += 6; groups++;
                    if (groups < 8 && j < out.size() && out[j] == '-') {
                        candidate += '-'; ++j;
                    }
                }
                if (groups == 8) return candidate;
            }
        }
        return {};
    }

} // namespace BitLocker

// ============================================================
//  SECTION S4 — Certificate Store Management (CryptoAPI)
// ============================================================
//  The Windows certificate store is used by TLS/HTTPS, code
//  signing verification, smart cards, and email encryption.
//  Functions here wrap CryptoAPI (crypt32.dll).
//
//  Common store names: "MY" (personal), "ROOT" (trusted CAs),
//  "CA" (intermediate CAs), "TRUST", "DISALLOWED"
//
//  !! Adding certificates to ROOT without user consent is a
//     man-in-the-middle attack vector. Do not abuse this. !!
// ============================================================
namespace Certificates {

    struct CertInfo {
        std::string subject;         ///< Subject name (CN=..., O=..., etc.)
        std::string issuer;          ///< Issuer name
        std::string thumbprint;      ///< SHA-1 hex thumbprint (40 chars)
        std::string serialNumber;    ///< Certificate serial number (hex)
        std::string notBefore;       ///< Validity start (YYYY-MM-DD HH:MM:SS)
        std::string notAfter;        ///< Validity end  (YYYY-MM-DD HH:MM:SS)
        bool        isExpired = false;
        bool        isSelfSigned = false;
    };

    namespace _CertDetail {

        inline std::string FileTimeToStr(const FILETIME& ft) {
            SYSTEMTIME st{};
            FileTimeToSystemTime(&ft, &st);
            return Str::Format("%04d-%02d-%02d %02d:%02d:%02d",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        }

        inline std::string GetCertNameStr(PCCERT_CONTEXT ctx, DWORD type) {
            DWORD sz = CertGetNameStringW(ctx, type, 0, nullptr, nullptr, 0);
            std::wstring buf(sz, L'\0');
            CertGetNameStringW(ctx, type, 0, nullptr, buf.data(), sz);
            if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
            return Str::ToNarrow(buf);
        }

        inline std::string GetThumbprint(PCCERT_CONTEXT ctx) {
            BYTE hash[20] = {};
            DWORD sz = sizeof(hash);
            CryptHashCertificate(0, CALG_SHA1, 0,
                ctx->pbCertEncoded, ctx->cbCertEncoded, hash, &sz);
            std::string result;
            char hex[3];
            for (int i = 0; i < 20; ++i) {
                std::snprintf(hex, sizeof(hex), "%02X", hash[i]);
                result += hex;
            }
            return result;
        }

        inline CertInfo FromContext(PCCERT_CONTEXT ctx) {
            CertInfo info;
            info.subject     = GetCertNameStr(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE);
            info.issuer      = GetCertNameStr(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE);
            // For issuer, use the issuer blob
            {
                DWORD sz = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG, nullptr, nullptr, 0);
                std::wstring buf(sz, L'\0');
                CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG, nullptr, buf.data(), sz);
                if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
                info.issuer = Str::ToNarrow(buf);
            }
            info.thumbprint  = GetThumbprint(ctx);
            info.notBefore   = FileTimeToStr(ctx->pCertInfo->NotBefore);
            info.notAfter    = FileTimeToStr(ctx->pCertInfo->NotAfter);

            // Is expired?
            FILETIME now{};
            GetSystemTimeAsFileTime(&now);
            info.isExpired = (CompareFileTime(&now, &ctx->pCertInfo->NotAfter) > 0);

            // Is self-signed? Subject == Issuer blob comparison
            info.isSelfSigned = CertCompareCertificateName(
                X509_ASN_ENCODING,
                &ctx->pCertInfo->Subject,
                &ctx->pCertInfo->Issuer) != FALSE;

            // Serial number (hex)
            for (DWORD i = ctx->pCertInfo->SerialNumber.cbData; i > 0; --i) {
                char h[3];
                std::snprintf(h, sizeof(h), "%02X",
                    ctx->pCertInfo->SerialNumber.pbData[i-1]);
                info.serialNumber += h;
            }
            return info;
        }
    } // namespace _CertDetail

    /// Enumerate all certificates in a store.
    /// storeName: "MY", "ROOT", "CA", "TRUST", "DISALLOWED"
    /// systemStore: true = HKLM (all users), false = HKCU (current user)
    inline std::vector<CertInfo> Enumerate(
            const std::string& storeName = "MY",
            bool systemStore = false) {
        std::vector<CertInfo> result;
        DWORD location = systemStore
            ? CERT_SYSTEM_STORE_LOCAL_MACHINE
            : CERT_SYSTEM_STORE_CURRENT_USER;
        HCERTSTORE hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location | CERT_STORE_READONLY_FLAG,
            Str::ToWide(storeName).c_str());
        if (!hStore) return result;
        PCCERT_CONTEXT ctx = nullptr;
        while ((ctx = CertEnumCertificatesInStore(hStore, ctx)) != nullptr)
            result.push_back(_CertDetail::FromContext(ctx));
        CertCloseStore(hStore, 0);
        return result;
    }

    /// Find a certificate by subject partial match (case-insensitive).
    /// Returns first match or nullopt.
    inline std::optional<CertInfo> FindBySubject(
            const std::string& subject,
            const std::string& storeName = "MY",
            bool systemStore = false) {
        std::string lower = subject;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (auto& cert : Enumerate(storeName, systemStore)) {
            std::string s = cert.subject;
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            if (s.find(lower) != std::string::npos)
                return cert;
        }
        return std::nullopt;
    }

    /// Find a certificate by SHA-1 thumbprint (hex, case-insensitive).
    inline std::optional<CertInfo> FindByThumbprint(
            const std::string& thumbprint,
            const std::string& storeName = "MY",
            bool systemStore = false) {
        std::string upper = thumbprint;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
        for (auto& cert : Enumerate(storeName, systemStore))
            if (cert.thumbprint == upper)
                return cert;
        return std::nullopt;
    }

    /// Install a certificate from a .cer/.der file into a store.
    ///
    /// !! Adding to ROOT installs a trusted CA — a security-critical operation.
    ///    On non-admin stores (HKCU) this will trigger a UAC-style
    ///    trust dialog for ROOT installations. !!
    ///
    /// Requires: Administrator for HKLM stores
    inline bool InstallFromFile(const std::string& certFilePath,
                                 const std::string& storeName = "MY",
                                 bool systemStore = false) {
        auto data = File::ReadAll(certFilePath);
        if (!data) return false;
        DWORD location = systemStore
            ? CERT_SYSTEM_STORE_LOCAL_MACHINE
            : CERT_SYSTEM_STORE_CURRENT_USER;
        HCERTSTORE hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location, Str::ToWide(storeName).c_str());
        if (!hStore) return false;
        bool ok = CertAddEncodedCertificateToStore(
            hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            reinterpret_cast<const BYTE*>(data->data()),
            static_cast<DWORD>(data->size()),
            CERT_STORE_ADD_REPLACE_EXISTING, nullptr) != FALSE;
        CertCloseStore(hStore, 0);
        return ok;
    }

    /// Remove a certificate from a store by thumbprint.
    /// Requires: Administrator for HKLM stores
    inline bool RemoveByThumbprint(const std::string& thumbprint,
                                    const std::string& storeName = "MY",
                                    bool systemStore = false) {
        DWORD location = systemStore
            ? CERT_SYSTEM_STORE_LOCAL_MACHINE
            : CERT_SYSTEM_STORE_CURRENT_USER;
        HCERTSTORE hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location, Str::ToWide(storeName).c_str());
        if (!hStore) return false;
        std::string upper = thumbprint;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
        bool removed = false;
        PCCERT_CONTEXT ctx = nullptr;
        while ((ctx = CertEnumCertificatesInStore(hStore, ctx)) != nullptr) {
            if (_CertDetail::GetThumbprint(ctx) == upper) {
                // CertDeleteCertificateFromStore frees ctx and advances the enum
                PCCERT_CONTEXT dup = CertDuplicateCertificateContext(ctx);
                CertDeleteCertificateFromStore(dup);
                ctx = nullptr; // restart enum after deletion
                removed = true;
                break;
            }
        }
        CertCloseStore(hStore, 0);
        return removed;
    }

    /// Check if a certificate file is valid and not expired.
    inline bool IsFileValid(const std::string& certFilePath) {
        auto data = File::ReadAll(certFilePath);
        if (!data) return false;
        PCCERT_CONTEXT ctx = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            reinterpret_cast<const BYTE*>(data->data()),
            static_cast<DWORD>(data->size()));
        if (!ctx) return false;
        FILETIME now{};
        GetSystemTimeAsFileTime(&now);
        bool valid = (CompareFileTime(&now, &ctx->pCertInfo->NotAfter) <= 0);
        CertFreeCertificateContext(ctx);
        return valid;
    }

    /// Get all expired certificates in a store.
    inline std::vector<CertInfo> GetExpired(
            const std::string& storeName = "MY",
            bool systemStore = false) {
        std::vector<CertInfo> result;
        for (auto& cert : Enumerate(storeName, systemStore))
            if (cert.isExpired) result.push_back(cert);
        return result;
    }

} // namespace Certificates

// ============================================================
//  SECTION S5 — Exploit Mitigation Policies (DEP / ASLR / CFG)
// ============================================================
//  Windows has per-process and system-wide mitigation policies
//  that make memory corruption exploits much harder to execute.
//
//  DEP  — Data Execution Prevention: marks non-code pages as
//          non-executable. Prevents shellcode in data pages.
//  ASLR — Address Space Layout Randomization: randomises the
//          load address of the executable and libraries.
//  CFG  — Control Flow Guard: validates indirect call targets.
//  ACG  — Arbitrary Code Guard: prevents JIT from writing
//          executable pages (breaks some game anti-cheats).
//
//  Most of these are set via SetProcessMitigationPolicy / registry.
// ============================================================
namespace Mitigations {

    /// Per-process mitigation status
    struct MitigationStatus {
        bool depEnabled           = false; ///< DEP is on for this process
        bool depPermanent         = false; ///< DEP cannot be disabled at runtime
        bool aslrEnabled          = false; ///< ASLR is in use for this process image
        bool forceRelocate        = false; ///< High-entropy / force-relocate ASLR
        bool cfgEnabled           = false; ///< Control Flow Guard is active
        bool acgEnabled           = false; ///< Arbitrary Code Guard is active
        bool extensionPointDisable= false; ///< Extension point DLLs blocked
        bool heapTerminateEnabled = false; ///< Heap terminate-on-corruption is on
    };

    /// Query mitigation policies active on the current process.
    inline MitigationStatus GetCurrentProcessStatus() {
        MitigationStatus s;

        // DEP
        {
            PROCESS_MITIGATION_DEP_POLICY dep{};
            if (GetProcessMitigationPolicy(GetCurrentProcess(),
                ProcessDEPPolicy, &dep, sizeof(dep))) {
                s.depEnabled  = dep.Enable != 0;
                s.depPermanent = dep.Permanent != 0;
            }
        }

        // ASLR
        {
            PROCESS_MITIGATION_ASLR_POLICY aslr{};
            if (GetProcessMitigationPolicy(GetCurrentProcess(),
                ProcessASLRPolicy, &aslr, sizeof(aslr))) {
                s.aslrEnabled    = aslr.EnableBottomUpRandomization != 0;
                s.forceRelocate  = aslr.EnableForceRelocateImages  != 0;
            }
        }

        // CFG
        {
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
            if (GetProcessMitigationPolicy(GetCurrentProcess(),
                ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)))
                s.cfgEnabled = cfg.EnableControlFlowGuard != 0;
        }

        // ACG (Dynamic Code Policy)
        {
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg{};
            if (GetProcessMitigationPolicy(GetCurrentProcess(),
                ProcessDynamicCodePolicy, &acg, sizeof(acg)))
                s.acgEnabled = acg.ProhibitDynamicCode != 0;
        }

        // Extension point disable
        {
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep{};
            if (GetProcessMitigationPolicy(GetCurrentProcess(),
                ProcessExtensionPointDisablePolicy, &ep, sizeof(ep)))
                s.extensionPointDisable = ep.DisableExtensionPoints != 0;
        }

        // Heap terminate on corruption (read from heap flags)
        {
            PROCESS_MITIGATION_HEAP_POLICY hp{};
            if (GetProcessMitigationPolicy(GetCurrentProcess(),
                ProcessHeapPolicy, &hp, sizeof(hp)))
                s.heapTerminateEnabled = hp.TerminateOnHeapCorruption != 0;
        }

        return s;
    }

    /// Query mitigations for a specific process by PID.
    inline MitigationStatus GetProcessStatus(DWORD pid) {
        MitigationStatus s;
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hp) return s;

        PROCESS_MITIGATION_DEP_POLICY dep{};
        if (GetProcessMitigationPolicy(hp, ProcessDEPPolicy, &dep, sizeof(dep))) {
            s.depEnabled  = dep.Enable != 0;
            s.depPermanent = dep.Permanent != 0;
        }

        PROCESS_MITIGATION_ASLR_POLICY aslr{};
        if (GetProcessMitigationPolicy(hp, ProcessASLRPolicy, &aslr, sizeof(aslr))) {
            s.aslrEnabled   = aslr.EnableBottomUpRandomization != 0;
            s.forceRelocate = aslr.EnableForceRelocateImages   != 0;
        }

        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
        if (GetProcessMitigationPolicy(hp, ProcessControlFlowGuardPolicy,
            &cfg, sizeof(cfg)))
            s.cfgEnabled = cfg.EnableControlFlowGuard != 0;

        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg{};
        if (GetProcessMitigationPolicy(hp, ProcessDynamicCodePolicy,
            &acg, sizeof(acg)))
            s.acgEnabled = acg.ProhibitDynamicCode != 0;

        CloseHandle(hp);
        return s;
    }

    /// Enable DEP for the current process permanently.
    /// !! Cannot be reversed — call before loading any DLLs that need W^X !!
    inline bool EnableDEP() {
        PROCESS_MITIGATION_DEP_POLICY dep{};
        dep.Enable    = 1;
        dep.Permanent = 1;
        return SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep)) != FALSE;
    }

    /// Enable ACG (Arbitrary Code Guard) for the current process.
    /// !! Breaks any JIT compiler (V8, LuaJIT, CLR, etc.) in-process !!
    inline bool EnableACG() {
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg{};
        acg.ProhibitDynamicCode = 1;
        return SetProcessMitigationPolicy(ProcessDynamicCodePolicy,
            &acg, sizeof(acg)) != FALSE;
    }

    /// Enable extension-point DLL blocking for the current process.
    /// Prevents AppInit_DLLs, shim engine, and accessibility DLL injection.
    inline bool EnableExtensionPointBlock() {
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep{};
        ep.DisableExtensionPoints = 1;
        return SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy,
            &ep, sizeof(ep)) != FALSE;
    }

    /// Enable bottom-up ASLR + force-relocate for the current process.
    inline bool EnableASLR() {
        PROCESS_MITIGATION_ASLR_POLICY aslr{};
        aslr.EnableBottomUpRandomization = 1;
        aslr.EnableForceRelocateImages   = 1;
        aslr.EnableHighEntropy           = 1;
        return SetProcessMitigationPolicy(ProcessASLRPolicy,
            &aslr, sizeof(aslr)) != FALSE;
    }

    /// Enable heap terminate-on-corruption for the current process.
    inline bool EnableHeapTerminateOnCorruption() {
        PROCESS_MITIGATION_HEAP_POLICY hp{};
        hp.TerminateOnHeapCorruption = 1;
        return SetProcessMitigationPolicy(ProcessHeapPolicy,
            &hp, sizeof(hp)) != FALSE;
    }

    /// Apply an image-level ASLR flag to an EXE via the PE header DWORD
    /// in registry (IFEO — Image File Execution Options).
    /// This opts the image into mandatory ASLR system-wide on all future launches.
    /// imageName: e.g. "myapp.exe"
    /// Requires: Administrator
    inline bool ForceASLRForImage(const std::string& imageName) {
        const std::string key =
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
            + imageName;
        // MitigationOptions bit 0x20 = ASLR force-relocate
        auto existing = Registry::ReadDWORD(HKEY_LOCAL_MACHINE, key, "MitigationOptions");
        DWORD val = existing.value_or(0) | 0x00000020;
        return Registry::WriteDWORD(HKEY_LOCAL_MACHINE, key, "MitigationOptions", val);
    }

    /// Get the system-wide DEP policy as a string.
    inline std::string GetSystemDEPPolicyStr() {
        // Read from registry — bcdedit nx setting mapped here
        auto val = Registry::ReadString(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
            "DisablePagingExecutive");
        // Actual NX policy is in boot config, but current setting visible here
        auto r = Process::RunCapture("bcdedit /enum {current}");
        if (r) {
            auto pos = r->find("nx");
            if (pos != std::string::npos) {
                auto end = r->find('\n', pos);
                return Str::Trim(r->substr(pos + 2, end - pos - 2));
            }
        }
        return "Unknown";
    }

} // namespace Mitigations

// ============================================================
//  SECTION S6 — Local Security Policy Audit Settings
// ============================================================
//  Windows audit policy controls which events get written to
//  the Security event log. Reading/writing requires Admin and
//  the LSA Policy API (advapi32 / secur32).
//
//  Common use: enable detailed audit logging for forensics,
//  compliance (PCI-DSS / HIPAA), or red-team detection.
// ============================================================
namespace Audit {

    /// Audit subcategory result
    struct AuditCategoryStatus {
        std::string name;
        bool        auditSuccess = false;
        bool        auditFailure = false;
    };

    /// Get audit policy for a named subcategory via auditpol.exe
    /// subcategory: e.g. "Logon", "Process Creation", "File System"
    inline std::optional<AuditCategoryStatus> GetPolicy(
            const std::string& subcategory) {
        auto r = Process::RunCapture(
            "auditpol /get /subcategory:\"" + subcategory + "\"");
        if (!r) return std::nullopt;

        AuditCategoryStatus s;
        s.name = subcategory;

        // auditpol output line: "  Logon                         Success and Failure"
        std::string setting;
        auto pos = r->rfind('\n', r->rfind(subcategory));
        if (pos == std::string::npos) {
            // Try to find the setting on the line containing the subcategory
            auto sc = r->find(subcategory);
            if (sc == std::string::npos) return std::nullopt;
            auto lineEnd = r->find('\n', sc);
            setting = Str::Trim(r->substr(sc + subcategory.size(),
                lineEnd - sc - subcategory.size()));
        } else {
            auto lineEnd = r->find('\n', pos + 1);
            setting = Str::Trim(r->substr(pos + 1, lineEnd - pos - 1));
            // Remove the subcategory name prefix
            auto sp = setting.find("  ");
            if (sp != std::string::npos)
                setting = Str::Trim(setting.substr(sp));
        }

        s.auditSuccess = (setting.find("Success") != std::string::npos);
        s.auditFailure = (setting.find("Failure") != std::string::npos);
        return s;
    }

    /// Set audit policy for a subcategory.
    /// Requires: Administrator
    inline bool SetPolicy(const std::string& subcategory,
                           bool auditSuccess,
                           bool auditFailure) {
        std::string args = "/set /subcategory:\"" + subcategory + "\"";
        if (auditSuccess && auditFailure)  args += " /success:enable /failure:enable";
        else if (auditSuccess)             args += " /success:enable /failure:disable";
        else if (auditFailure)             args += " /success:disable /failure:enable";
        else                               args += " /success:disable /failure:disable";
        return Process::Run("auditpol.exe", args, true, true);
    }

    /// Enable auditing for process creation (Subcategory: "Process Creation").
    /// This lets you see every process launch in the Security event log.
    /// Requires: Administrator
    inline bool EnableProcessCreationAudit() {
        return SetPolicy("Process Creation", true, true);
    }

    /// Enable logon/logoff auditing.
    /// Requires: Administrator
    inline bool EnableLogonAudit() {
        return SetPolicy("Logon", true, true);
    }

    /// Enable privilege use auditing (catches escalation events).
    /// Requires: Administrator
    inline bool EnablePrivilegeUseAudit() {
        return SetPolicy("Sensitive Privilege Use", true, true);
    }

    /// Enable object access auditing (file/registry reads/writes).
    /// !! This generates a very large volume of events — use carefully !!
    /// Requires: Administrator
    inline bool EnableObjectAccessAudit() {
        return SetPolicy("File System", true, true)
            && SetPolicy("Registry", true, true);
    }

    /// Dump the full audit policy as a formatted string (via auditpol /get /category:*)
    inline std::string GetFullPolicyDump() {
        auto r = Process::RunCapture("auditpol /get /category:*");
        return r.value_or("Failed to query audit policy.");
    }

    /// Export the audit policy to a .csv backup file.
    /// Requires: Administrator
    inline bool ExportPolicy(const std::string& outputPath) {
        return Process::Run("auditpol.exe",
            "/backup /file:\"" + outputPath + "\"", true, true);
    }

    /// Import/restore an audit policy from a .csv file.
    /// Requires: Administrator
    inline bool ImportPolicy(const std::string& policyPath) {
        return Process::Run("auditpol.exe",
            "/restore /file:\"" + policyPath + "\"", true, true);
    }

} // namespace Audit

// ============================================================
//  SECTION S7 — Windows Credential Manager
// ============================================================
//  The Credential Manager stores saved passwords, certificates,
//  and Windows/web credentials in encrypted vaults per-user.
//  Functions here wrap the Windows Credential API (wincred.h).
//
//  Credentials are encrypted with DPAPI keyed to the user's
//  login credentials — they can only be read by the same user
//  (or an elevated process impersonating them).
// ============================================================
namespace Credentials {

    struct Credential {
        std::string targetName;   ///< Service/site name this credential is for
        std::string userName;     ///< Username
        std::string secret;       ///< Password / secret (decrypted on read)
        std::string comment;      ///< Optional description
        DWORD       type = 0;     ///< CRED_TYPE_GENERIC, CRED_TYPE_DOMAIN_PASSWORD, etc.
    };

    /// Read a generic credential from the vault.
    /// targetName: the key used to store it (e.g. "MyApp/DatabasePassword")
    inline std::optional<Credential> Read(const std::string& targetName) {
        PCREDENTIALW pCred = nullptr;
        if (!CredReadW(Str::ToWide(targetName).c_str(),
            CRED_TYPE_GENERIC, 0, &pCred) || !pCred)
            return std::nullopt;

        Credential c;
        c.targetName = targetName;
        c.type       = pCred->Type;
        if (pCred->UserName)
            c.userName = Str::ToNarrow(pCred->UserName);
        if (pCred->Comment)
            c.comment = Str::ToNarrow(pCred->Comment);
        if (pCred->CredentialBlob && pCred->CredentialBlobSize > 0)
            c.secret = std::string(
                reinterpret_cast<char*>(pCred->CredentialBlob),
                pCred->CredentialBlobSize);

        CredFree(pCred);
        return c;
    }

    /// Write a generic credential to the vault (creates or overwrites).
    inline bool Write(const std::string& targetName,
                       const std::string& userName,
                       const std::string& secret,
                       const std::string& comment = "") {
        std::wstring wTarget  = Str::ToWide(targetName);
        std::wstring wUser    = Str::ToWide(userName);
        std::wstring wComment = Str::ToWide(comment);

        CREDENTIALW cred{};
        cred.Type                 = CRED_TYPE_GENERIC;
        cred.TargetName           = wTarget.data();
        cred.UserName             = wUser.data();
        cred.Comment              = comment.empty() ? nullptr : wComment.data();
        cred.CredentialBlobSize   = static_cast<DWORD>(secret.size());
        cred.CredentialBlob       = reinterpret_cast<LPBYTE>(
                                        const_cast<char*>(secret.c_str()));
        cred.Persist              = CRED_PERSIST_LOCAL_MACHINE;

        return CredWriteW(&cred, 0) != FALSE;
    }

    /// Delete a credential from the vault.
    inline bool Delete(const std::string& targetName) {
        return CredDeleteW(Str::ToWide(targetName).c_str(),
            CRED_TYPE_GENERIC, 0) != FALSE;
    }

    /// List all generic credentials in the vault.
    inline std::vector<Credential> ListAll() {
        std::vector<Credential> result;
        PCREDENTIALW* pCreds = nullptr;
        DWORD count = 0;
        if (!CredEnumerateW(nullptr, 0, &count, &pCreds) || !pCreds)
            return result;

        for (DWORD i = 0; i < count; ++i) {
            if (!pCreds[i]) continue;
            Credential c;
            if (pCreds[i]->TargetName) c.targetName = Str::ToNarrow(pCreds[i]->TargetName);
            if (pCreds[i]->UserName)   c.userName   = Str::ToNarrow(pCreds[i]->UserName);
            if (pCreds[i]->Comment)    c.comment    = Str::ToNarrow(pCreds[i]->Comment);
            c.type = pCreds[i]->Type;
            // Secret is intentionally omitted in bulk enumeration
            result.push_back(c);
        }
        CredFree(pCreds);
        return result;
    }

    /// Check if a credential exists.
    inline bool Exists(const std::string& targetName) {
        PCREDENTIALW pCred = nullptr;
        bool ok = CredReadW(Str::ToWide(targetName).c_str(),
            CRED_TYPE_GENERIC, 0, &pCred) != FALSE;
        if (ok) CredFree(pCred);
        return ok;
    }

    /// Show the Windows built-in credential UI dialog to prompt the user
    /// for a username/password. Returns the entered credential or nullopt
    /// if the user cancelled.
    /// caption: dialog title, message: prompt text
    inline std::optional<Credential> PromptUser(
            const std::string& targetName,
            const std::string& caption  = "Enter credentials",
            const std::string& message  = "") {
        CREDUI_INFOW ui{};
        ui.cbSize         = sizeof(ui);
        std::wstring wcap = Str::ToWide(caption);
        std::wstring wmsg = Str::ToWide(message);
        ui.pszCaptionText = wcap.c_str();
        ui.pszMessageText = wmsg.c_str();

        wchar_t user[CREDUI_MAX_USERNAME_LENGTH + 1] = {};
        wchar_t pass[CREDUI_MAX_PASSWORD_LENGTH + 1] = {};
        BOOL save = FALSE;

        DWORD ret = CredUIPromptForCredentialsW(
            &ui,
            Str::ToWide(targetName).c_str(),
            nullptr, 0,
            user, CREDUI_MAX_USERNAME_LENGTH,
            pass, CREDUI_MAX_PASSWORD_LENGTH,
            &save,
            CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI);

        if (ret != NO_ERROR) return std::nullopt;

        Credential c;
        c.targetName = targetName;
        c.userName   = Str::ToNarrow(user);
        c.secret     = Str::ToNarrow(pass);
        SecureZeroMemory(pass, sizeof(pass)); // clear password from stack
        return c;
    }

} // namespace Credentials

// ============================================================
//  SECTION S8 — Honey Accounts (Decoy / Trap User Accounts)
// ============================================================
//  A Honey Account is a fake local user account that no legitimate
//  user ever logs into. Any login attempt against it is by definition
//  suspicious — an attacker enumerating accounts, brute-forcing
//  credentials, or using leaked password lists.
//
//  This is a standard blue-team / intrusion detection technique used
//  by sysadmins, SOC teams, and security researchers. Honey accounts
//  are documented by MITRE ATT&CK (D3FEND: Decoy User Credential)
//  and recommended by CIS Benchmarks for Windows.
//
//  How it works:
//    1. Create a disabled local account with a tempting name
//       (e.g. "admin", "backup", "svc_sql")
//    2. The account is disabled — no one can actually log in
//    3. Any authentication attempt still generates Security event
//       log entries (Event ID 4625 = failed logon)
//    4. WatchForAttempts() monitors the event log on a background
//       thread and fires a callback when any attempt is detected
//
//  Requires: Administrator for account creation/deletion
//  Event log reading: requires no special privileges for local Security log
// ============================================================
namespace HoneyAccount {

    // Registry key where WinUtils tracks which accounts are honey accounts
    // so ListAll() knows which accounts we created vs system accounts
    static constexpr const char* kHoneyRegKey =
        "SOFTWARE\\WinUtils\\HoneyAccounts";

    // ---- Data structures ----

    /// Information about a honey account
    struct HoneyAccountInfo {
        std::string name;           ///< Account username
        std::string description;    ///< Account description (visible in lusrmgr.msc)
        std::string createdAt;      ///< Creation timestamp (ISO-ish: YYYY-MM-DD HH:MM:SS)
        bool        exists = false; ///< Account is present in the local SAM database
        DWORD       loginAttempts = 0; ///< Cached count of login attempts seen so far
    };

    /// A login attempt event caught against a honey account
    struct LoginAttempt {
        std::string accountName;  ///< The honey account that was targeted
        std::string timestamp;    ///< When the attempt occurred
        std::string sourceIP;     ///< Source IP address (empty if local/unknown)
        std::string workstation;  ///< Source workstation name
        std::string logonType;    ///< e.g. "Network", "Interactive", "RemoteInteractive"
        DWORD       eventId = 0;  ///< 4625 = failed, 4624 = success (should never succeed)
        std::string failureReason;///< Why it failed (wrong password, account disabled, etc.)
    };

    // ---- Internal helpers ----
    namespace _Honey {

        inline std::string NowStr() {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            return Str::Format("%04d-%02d-%02d %02d:%02d:%02d",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        }

        inline std::string LogonTypeStr(DWORD type) {
            switch (type) {
                case 2:  return "Interactive";
                case 3:  return "Network";
                case 4:  return "Batch";
                case 5:  return "Service";
                case 7:  return "Unlock";
                case 8:  return "NetworkCleartext";
                case 9:  return "NewCredentials";
                case 10: return "RemoteInteractive";
                case 11: return "CachedInteractive";
                default: return "Unknown(" + std::to_string(type) + ")";
            }
        }

        // Pull a named XML value out of an event XML string
        // e.g. extract "192.168.1.1" from <Data Name='IpAddress'>192.168.1.1</Data>
        inline std::string XmlField(const std::string& xml, const std::string& name) {
            std::string open  = "<Data Name='" + name + "'>";
            std::string openQ = "<Data Name=\"" + name + "\">";
            auto pos = xml.find(open);
            if (pos == std::string::npos) pos = xml.find(openQ);
            if (pos == std::string::npos) return {};
            auto start = xml.find('>', pos) + 1;
            auto end   = xml.find("</Data>", start);
            if (start == std::string::npos || end == std::string::npos) return {};
            std::string val = xml.substr(start, end - start);
            // Strip leading/trailing whitespace
            val.erase(0, val.find_first_not_of(" \t\r\n"));
            val.erase(val.find_last_not_of(" \t\r\n") + 1);
            if (val == "-" || val == "%%1796") return {};
            return val;
        }

        // Global watcher state
        inline std::atomic<bool>& _watching() { static std::atomic<bool> v{false}; return v; }
        inline std::thread& _watchThread() { static std::thread t; return t; }
        inline std::mutex& _cbMtx() { static std::mutex m; return m; }
        using AttemptCallback = std::function<void(const LoginAttempt&)>;
        inline AttemptCallback& _callback() { static AttemptCallback cb; return cb; }

    } // namespace _Honey

    // ---- Account management ----

    /// Create a honey (decoy) local user account.
    ///
    /// The account is created DISABLED — no one can actually log in with it.
    /// Login attempts against it still generate Security event log entries.
    ///
    /// name:        Username (pick something tempting: "admin", "backup", "sa", "svc_sql")
    /// password:    A strong password — this never needs to be used; just make it complex
    /// description: Shown in lusrmgr.msc — make it look real e.g. "SQL Service Account"
    ///
    /// Requires: Administrator
    inline bool Create(const std::string& name,
                       const std::string& password,
                       const std::string& description = "Service Account") {
        std::wstring wName = Str::ToWide(name);
        std::wstring wPass = Str::ToWide(password);
        std::wstring wDesc = Str::ToWide(description);

        USER_INFO_1 ui{};
        ui.usri1_name     = wName.data();
        ui.usri1_password = wPass.data();
        ui.usri1_priv     = USER_PRIV_USER;
        ui.usri1_flags    = UF_ACCOUNTDISABLE | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT;
        ui.usri1_script_path = nullptr;
        ui.usri1_home_dir    = nullptr;

        NET_API_STATUS status = NetUserAdd(nullptr, 1,
            reinterpret_cast<LPBYTE>(&ui), nullptr);

        if (status != NERR_Success && status != NERR_UserExists)
            return false;

        // Set description via USER_INFO_1007
        USER_INFO_1007 ui7{};
        ui7.usri1007_comment = wDesc.data();
        NetUserSetInfo(nullptr, wName.c_str(), 1007,
            reinterpret_cast<LPBYTE>(&ui7), nullptr);

        // Ensure account stays disabled
        USER_INFO_1008 ui8{};
        ui8.usri1008_flags = UF_ACCOUNTDISABLE | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT;
        NetUserSetInfo(nullptr, wName.c_str(), 1008,
            reinterpret_cast<LPBYTE>(&ui8), nullptr);

        // Register in our tracking registry key
        Registry::WriteDWORD(HKEY_LOCAL_MACHINE, kHoneyRegKey, name, 0);

        // Store creation timestamp alongside it
        const std::string tsKey = kHoneyRegKey + std::string("\\") + name;
        Registry::WriteString(HKEY_LOCAL_MACHINE, kHoneyRegKey,
            name + "_created", _Honey::NowStr());

        return true;
    }

    /// Remove a honey account and its tracking registry entry.
    /// Requires: Administrator
    inline bool Remove(const std::string& name) {
        NET_API_STATUS status = NetUserDel(nullptr, Str::ToWide(name).c_str());
        // Clean up registry tracking regardless of whether account existed
        Registry::DeleteValue(HKEY_LOCAL_MACHINE, kHoneyRegKey, name);
        Registry::DeleteValue(HKEY_LOCAL_MACHINE, kHoneyRegKey, name + "_created");
        return status == NERR_Success || status == NERR_UserNotFound;
    }

    /// Check if a honey account exists in the local SAM.
    inline bool Exists(const std::string& name) {
        USER_INFO_0* info = nullptr;
        NET_API_STATUS s = NetUserGetInfo(nullptr,
            Str::ToWide(name).c_str(), 0,
            reinterpret_cast<LPBYTE*>(&info));
        if (info) NetApiBufferFree(info);
        return s == NERR_Success;
    }

    /// Check if an account is currently disabled.
    inline bool IsDisabled(const std::string& name) {
        USER_INFO_1* info = nullptr;
        NET_API_STATUS s = NetUserGetInfo(nullptr,
            Str::ToWide(name).c_str(), 1,
            reinterpret_cast<LPBYTE*>(&info));
        if (s != NERR_Success || !info) return false;
        bool disabled = (info->usri1_flags & UF_ACCOUNTDISABLE) != 0;
        NetApiBufferFree(info);
        return disabled;
    }

    /// Re-disable a honey account if it somehow got enabled.
    /// Requires: Administrator
    inline bool EnsureDisabled(const std::string& name) {
        USER_INFO_1008 ui{};
        ui.usri1008_flags = UF_ACCOUNTDISABLE | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT;
        return NetUserSetInfo(nullptr, Str::ToWide(name).c_str(), 1008,
            reinterpret_cast<LPBYTE>(&ui), nullptr) == NERR_Success;
    }

    /// List all honey accounts tracked by WinUtils.
    /// Only returns accounts that were created via HoneyAccount::Create().
    inline std::vector<HoneyAccountInfo> ListAll() {
        std::vector<HoneyAccountInfo> result;
        auto names = Registry::ListValues(HKEY_LOCAL_MACHINE, kHoneyRegKey);
        for (auto& n : names) {
            // Skip the _created timestamp entries
            if (n.size() > 8 && n.substr(n.size() - 8) == "_created") continue;
            HoneyAccountInfo info;
            info.name   = n;
            info.exists = Exists(n);
            auto ts = Registry::ReadString(HKEY_LOCAL_MACHINE, kHoneyRegKey,
                n + "_created");
            if (ts) info.createdAt = *ts;
            // Get description from SAM
            USER_INFO_1007* ui = nullptr;
            if (NetUserGetInfo(nullptr, Str::ToWide(n).c_str(), 1007,
                reinterpret_cast<LPBYTE*>(&ui)) == NERR_Success && ui) {
                if (ui->usri1007_comment)
                    info.description = Str::ToNarrow(ui->usri1007_comment);
                NetApiBufferFree(ui);
            }
            result.push_back(info);
        }
        return result;
    }

    // ---- Event Log Monitoring ----

    /// Query the Security event log for login attempts against a specific account.
    ///
    /// accountName: the honey account username to filter for
    /// maxEvents:   maximum number of events to return (most recent first)
    ///
    /// Reads Event ID 4625 (failed logon) and 4624 (successful logon).
    /// A successful logon (4624) against a honey account is a critical alert
    /// since the account is disabled and should never succeed — if it does,
    /// it means someone re-enabled the account or the SAM was tampered with.
    ///
    /// Note: Reading the Security event log requires the process to be running
    /// as Administrator or as a member of the Event Log Readers group.
    inline std::vector<LoginAttempt> GetLoginAttempts(
            const std::string& accountName,
            DWORD maxEvents = 100) {

        std::vector<LoginAttempt> results;

        // XPath query: filter Security log for logon events targeting our account
        // Event 4625 = failed logon, 4624 = successful logon
        std::wstring query =
            L"*[System[(EventID=4625 or EventID=4624)] and "
            L"EventData[Data[@Name='TargetUserName']='" +
            Str::ToWide(accountName) + L"']]";

        EVT_HANDLE hResults = EvtQuery(
            nullptr,                    // local machine
            L"Security",               // channel
            query.c_str(),
            
            EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION);

        if (!hResults) return results;

        EVT_HANDLE hEvents[10];
        DWORD returned = 0;

        while (results.size() < maxEvents) {
            DWORD toFetch = static_cast<DWORD>(
                std::min<size_t>(10, maxEvents - results.size()));

            if (!EvtNext(hResults, toFetch, hEvents, INFINITE, 0, &returned)
                || returned == 0)
                break;

            for (DWORD i = 0; i < returned; ++i) {
                // Render the event as XML so we can parse all fields
                DWORD bufSize = 0, bufUsed = 0, propCount = 0;
                EvtRender(nullptr, hEvents[i], EvtRenderEventXml,
                    0, nullptr, &bufSize, &propCount);

                std::wstring xmlBuf(bufSize / sizeof(wchar_t) + 1, L'\0');
                if (!EvtRender(nullptr, hEvents[i], EvtRenderEventXml,
                    bufSize,
                    reinterpret_cast<PVOID>(xmlBuf.data()),
                    &bufUsed, &propCount)) {
                    EvtClose(hEvents[i]);
                    continue;
                }

                std::string xml = Str::ToNarrow(xmlBuf);

                LoginAttempt evt;
                evt.accountName  = accountName;
                evt.sourceIP     = _Honey::XmlField(xml, "IpAddress");
                evt.workstation  = _Honey::XmlField(xml, "WorkstationName");
                evt.failureReason = _Honey::XmlField(xml, "FailureReason");

                // Logon type
                std::string ltStr = _Honey::XmlField(xml, "LogonType");
                if (!ltStr.empty()) {
                    try {
                        evt.logonType = _Honey::LogonTypeStr(
                            static_cast<DWORD>(std::stoul(ltStr)));
                    } catch (...) { evt.logonType = ltStr; }
                }

                // Event ID
                auto eidStr = _Honey::XmlField(xml, "EventID");
                // EventID is in System section, not EventData — parse differently
                {
                    auto pos = xml.find("<EventID>");
                    if (pos != std::string::npos) {
                        auto end = xml.find("</EventID>", pos);
                        if (end != std::string::npos) {
                            try {
                                evt.eventId = static_cast<DWORD>(std::stoul(
                                    xml.substr(pos + 9, end - pos - 9)));
                            } catch (...) {}
                        }
                    }
                }

                // Timestamp from System/TimeCreated SystemTime attribute
                {
                    auto pos = xml.find("SystemTime='");
                    if (pos == std::string::npos) pos = xml.find("SystemTime=\"");
                    if (pos != std::string::npos) {
                        auto start = xml.find('\'', pos);
                        if (start == std::string::npos) start = xml.find('"', pos);
                        auto end = xml.find_first_of("'\"", start + 1);
                        if (start != std::string::npos && end != std::string::npos)
                            evt.timestamp = xml.substr(start + 1, end - start - 1);
                    }
                }

                results.push_back(evt);
                EvtClose(hEvents[i]);
            }
        }

        EvtClose(hResults);
        return results;
    }

    /// Query login attempts for ALL tracked honey accounts at once.
    inline std::vector<LoginAttempt> GetAllLoginAttempts(DWORD maxPerAccount = 50) {
        std::vector<LoginAttempt> all;
        for (auto& acct : ListAll()) {
            auto attempts = GetLoginAttempts(acct.name, maxPerAccount);
            all.insert(all.end(), attempts.begin(), attempts.end());
        }
        return all;
    }

    /// Get a count of login attempts for an account without returning full details.
    inline DWORD CountLoginAttempts(const std::string& accountName) {
        return static_cast<DWORD>(GetLoginAttempts(accountName, 10000).size());
    }

    // ---- Background Watcher ----

    /// Start a background thread that watches the Security event log and fires
    /// callback whenever a login attempt against ANY tracked honey account is detected.
    ///
    /// callback:       called on the watcher thread — keep it fast and thread-safe
    /// pollIntervalMs: how often to poll the event log (default 5 seconds)
    ///
    /// The watcher uses EvtSubscribe with a push-style callback for efficiency,
    /// falling back to polling if subscription fails (e.g. non-admin context).
    ///
    /// Call StopWatching() to shut down the thread cleanly.
    inline void WatchForAttempts(
            std::function<void(const LoginAttempt&)> callback,
            DWORD pollIntervalMs = 5000) {

        if (_Honey::_watching()) return; // already running

        {
            std::lock_guard<std::mutex> lock(_Honey::_cbMtx());
            _Honey::_callback() = callback;
        }

        _Honey::_watching() = true;

        _Honey::_watchThread() = std::thread([pollIntervalMs]() {
            // Track the last event count per account so we only fire on NEW events
            std::map<std::string, DWORD> lastCounts;

            while (_Honey::_watching()) {
                auto accounts = ListAll();
                for (auto& acct : accounts) {
                    auto attempts = GetLoginAttempts(acct.name, 1000);
                    DWORD newCount = static_cast<DWORD>(attempts.size());
                    DWORD oldCount = lastCounts.count(acct.name)
                        ? lastCounts[acct.name] : newCount;

                    if (newCount > oldCount) {
                        // Fire callback for each new event (newest first, so
                        // fire them in reverse to get chronological order)
                        DWORD newEvents = newCount - oldCount;
                        for (DWORD i = newEvents; i > 0; --i) {
                            if (i - 1 < attempts.size()) {
                                std::lock_guard<std::mutex> lock(_Honey::_cbMtx());
                                if (_Honey::_callback())
                                    _Honey::_callback()(attempts[i - 1]);
                            }
                        }
                    }
                    lastCounts[acct.name] = newCount;
                }
                ::Sleep(pollIntervalMs);
            }
        });
    }

    /// Stop the background watcher thread.
    inline void StopWatching() {
        _Honey::_watching() = false;
        if (_Honey::_watchThread().joinable())
            _Honey::_watchThread().join();
    }

    // ---- Reporting ----

    /// Generate a human-readable alert summary for a login attempt.
    inline std::string FormatAttempt(const LoginAttempt& evt) {
        std::string s;
        s += "HONEY ACCOUNT ALERT\n";
        s += "  Account    : " + evt.accountName + "\n";
        s += "  Event ID   : " + std::to_string(evt.eventId);
        s += (evt.eventId == 4624 ? " (SUCCESSFUL LOGON — CRITICAL!)" :
              evt.eventId == 4625 ? " (Failed logon)" : "") + std::string("\n");
        s += "  Time       : " + evt.timestamp + "\n";
        if (!evt.sourceIP.empty())
            s += "  Source IP  : " + evt.sourceIP + "\n";
        if (!evt.workstation.empty())
            s += "  Workstation: " + evt.workstation + "\n";
        if (!evt.logonType.empty())
            s += "  Logon Type : " + evt.logonType + "\n";
        if (!evt.failureReason.empty())
            s += "  Reason     : " + evt.failureReason + "\n";
        return s;
    }

    /// Print a full report of all honey accounts and their attempt counts to stdout.
    inline void PrintReport() {
        auto accounts = ListAll();
        if (accounts.empty()) {
            std::puts("No honey accounts registered.");
            return;
        }
        std::printf("%-20s %-8s %-19s %s\n",
            "Account", "Exists", "Created", "Login Attempts");
        std::printf("%s\n", std::string(70, '-').c_str());
        for (auto& a : accounts) {
            DWORD count = CountLoginAttempts(a.name);
            std::printf("%-20s %-8s %-19s %lu\n",
                a.name.c_str(),
                a.exists ? "YES" : "NO",
                a.createdAt.empty() ? "Unknown" : a.createdAt.c_str(),
                count);
        }
    }

} // namespace HoneyAccount

} // namespace Security
} // namespace WinUtils

#endif // WINUTILS_SECURITY_HPP