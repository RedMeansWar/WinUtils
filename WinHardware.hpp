/*
 * ============================================================================
 * WinHardware.hpp
 * Part of the WinUtils project — Hardware & system information queries
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
 * This file uses WMI (Windows Management Instrumentation) and PDH (Performance
 * Data Helper) to query hardware and system information. Some queries require
 * Administrator privileges or specific hardware support to return valid data.
 *
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
#ifndef WIN_HARDWARE_HPP
#define WIN_HARDWARE_HPP

#include "WinUtils.hpp"

#include <pdh.h>
#include <pdhmsg.h>
#include <comdef.h>
#include <wbemidl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>

#pragma comment(lib, "ws2_32.lib")

// Ensure Winsock is initialized for WSAAddressToStringA
namespace _WSA {
    struct Init {
        Init()  { WSADATA w; WSAStartup(MAKEWORD(2,2), &w); }
        ~Init() { WSACleanup(); }
    };
    inline Init _init;
}

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")

namespace WinUtils {

// ============================================================
//  Internal WMI helper shared across Hardware namespaces
// ============================================================
namespace _HW {

    struct WMISession {
        IWbemLocator*  pLoc = nullptr;
        IWbemServices* pSvc = nullptr;
        bool           ok   = false;

        WMISession() {
            CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE, nullptr);
            if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr,
                CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                reinterpret_cast<void**>(&pLoc)))) return;
            if (FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),
                nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc))) {
                pLoc->Release(); pLoc = nullptr; return;
            }
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                nullptr, RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
            ok = true;
        }

        ~WMISession() {
            if (pSvc) pSvc->Release();
            if (pLoc) pLoc->Release();
        }

        // Run a WQL query, call cb(row) for each result row
        void Query(const std::string& wql,
                   std::function<void(IWbemClassObject*)> cb) {
            if (!ok) return;
            IEnumWbemClassObject* pEnum = nullptr;
            if (FAILED(pSvc->ExecQuery(_bstr_t(L"WQL"),
                _bstr_t(Str::ToWide(wql).c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnum))) return;
            IWbemClassObject* pObj = nullptr; ULONG ret = 0;
            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &ret) == S_OK) {
                cb(pObj); pObj->Release();
            }
            pEnum->Release();
        }

        // Get a single string property from an object
        static std::string GetStr(IWbemClassObject* obj, const std::string& prop) {
            VARIANT v; VariantInit(&v);
            if (FAILED(obj->Get(Str::ToWide(prop).c_str(), 0, &v, nullptr, nullptr)))
                return {};
            std::string result;
            if (v.vt == VT_BSTR && v.bstrVal)
                result = Str::ToNarrow(v.bstrVal);
            else {
                VARIANT s; VariantInit(&s);
                if (SUCCEEDED(VariantChangeType(&s, &v, 0, VT_BSTR)) && s.bstrVal)
                    result = Str::ToNarrow(s.bstrVal);
                VariantClear(&s);
            }
            VariantClear(&v);
            return Str::Trim(result);
        }

        static uint64_t GetU64(IWbemClassObject* obj, const std::string& prop) {
            std::string s = GetStr(obj, prop);
            if (s.empty()) return 0;
            try { return std::stoull(s); } catch (...) { return 0; }
        }

        static DWORD GetDW(IWbemClassObject* obj, const std::string& prop) {
            VARIANT v; VariantInit(&v);
            if (FAILED(obj->Get(Str::ToWide(prop).c_str(), 0, &v, nullptr, nullptr)))
                return 0;
            DWORD result = (v.vt == VT_I4 || v.vt == VT_UI4) ? static_cast<DWORD>(v.lVal) : 0;
            VariantClear(&v); return result;
        }
    };

} // namespace _HW

// ============================================================
//  SECTION H1 — CPU Information
// ============================================================
namespace CPU {

    struct CPUInfo {
        std::string name;
        std::string manufacturer;
        std::string socket;
        DWORD       cores        = 0;
        DWORD       logicalCores = 0;
        DWORD       maxClockMHz  = 0;
        DWORD       currentClockMHz = 0;
        std::string architecture;
        std::string cpuId;
        double      usagePercent = 0.0;
    };

    /// Get detailed CPU information
    inline CPUInfo GetInfo() {
        CPUInfo info;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_Processor", [&](IWbemClassObject* obj) {
            info.name            = _HW::WMISession::GetStr(obj, "Name");
            info.manufacturer    = _HW::WMISession::GetStr(obj, "Manufacturer");
            info.socket          = _HW::WMISession::GetStr(obj, "SocketDesignation");
            info.cores           = _HW::WMISession::GetDW(obj,  "NumberOfCores");
            info.logicalCores    = _HW::WMISession::GetDW(obj,  "NumberOfLogicalProcessors");
            info.maxClockMHz     = _HW::WMISession::GetDW(obj,  "MaxClockSpeed");
            info.currentClockMHz = _HW::WMISession::GetDW(obj,  "CurrentClockSpeed");
            info.cpuId           = _HW::WMISession::GetStr(obj,  "ProcessorId");
        });
        return info;
    }

    /// Get CPU name string
    inline std::string GetName() { return GetInfo().name; }

    /// Get number of physical cores
    inline DWORD GetCoreCount() { return GetInfo().cores; }

    /// Get number of logical processors (including hyperthreading)
    inline DWORD GetLogicalCount() { return GetInfo().logicalCores; }

    /// Get max clock speed in MHz
    inline DWORD GetMaxClockMHz() { return GetInfo().maxClockMHz; }

    /// Get current CPU usage percentage using PDH
    inline double GetUsagePercent() {
        PDH_HQUERY query; PDH_HCOUNTER counter;
        if (PdhOpenQuery(nullptr, 0, &query) != ERROR_SUCCESS) return -1.0;
        if (PdhAddEnglishCounterW(query, L"\\Processor(_Total)\\% Processor Time",
            0, &counter) != ERROR_SUCCESS) {
            PdhCloseQuery(query); return -1.0;
        }
        PdhCollectQueryData(query);
        ::Sleep(100);
        PdhCollectQueryData(query);
        PDH_FMT_COUNTERVALUE val;
        PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &val);
        PdhCloseQuery(query);
        return val.doubleValue;
    }

    /// Get per-core usage percentages
    inline std::vector<double> GetPerCoreUsage() {
        std::vector<double> result;
        PDH_HQUERY query;
        if (PdhOpenQuery(nullptr, 0, &query) != ERROR_SUCCESS) return result;
        std::vector<PDH_HCOUNTER> counters;
        DWORD cores = GetLogicalCount();
        for (DWORD i = 0; i < cores; ++i) {
            std::wstring path = L"\\Processor(" + std::to_wstring(i) + L")\\% Processor Time";
            PDH_HCOUNTER c;
            PdhAddEnglishCounterW(query, path.c_str(), 0, &c);
            counters.push_back(c);
        }
        PdhCollectQueryData(query);
        ::Sleep(100);
        PdhCollectQueryData(query);
        for (auto& c : counters) {
            PDH_FMT_COUNTERVALUE val;
            PdhGetFormattedCounterValue(c, PDH_FMT_DOUBLE, nullptr, &val);
            result.push_back(val.doubleValue);
        }
        PdhCloseQuery(query);
        return result;
    }

    /// Get CPU temperature in Celsius via WMI (requires Admin, hardware support)
    /// Returns -1 if not available
    inline double GetTemperatureCelsius() {
        _HW::WMISession wmi;
        // Switch to root\WMI namespace for thermal data
        if (wmi.pSvc) wmi.pSvc->Release();
        if (wmi.pLoc) {
            wmi.pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"),
                nullptr, nullptr, nullptr, 0, nullptr, nullptr, &wmi.pSvc);
        }
        double temp = -1.0;
        wmi.Query("SELECT * FROM MSAcpi_ThermalZoneTemperature", [&](IWbemClassObject* obj) {
            DWORD raw = _HW::WMISession::GetDW(obj, "CurrentTemperature");
            if (raw > 0) temp = (raw / 10.0) - 273.15; // Kelvin * 10 -> Celsius
        });
        return temp;
    }

} // namespace CPU

// ============================================================
//  SECTION H2 — GPU Information
// ============================================================
namespace GPU {

    struct GPUInfo {
        std::string name;
        std::string driverVersion;
        std::string driverDate;
        uint64_t    vramBytes    = 0;
        DWORD       currentHz    = 0;
        DWORD       xResolution  = 0;
        DWORD       yResolution  = 0;
        std::string status;
        std::string adapterRAM;
        std::string pnpDeviceId;
    };

    /// Get info for all GPUs
    inline std::vector<GPUInfo> GetAll() {
        std::vector<GPUInfo> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_VideoController", [&](IWbemClassObject* obj) {
            GPUInfo g;
            g.name          = _HW::WMISession::GetStr(obj, "Name");
            g.driverVersion = _HW::WMISession::GetStr(obj, "DriverVersion");
            g.driverDate    = _HW::WMISession::GetStr(obj, "DriverDate");
            g.vramBytes     = _HW::WMISession::GetU64(obj, "AdapterRAM");
            g.currentHz     = _HW::WMISession::GetDW(obj,  "CurrentRefreshRate");
            g.xResolution   = _HW::WMISession::GetDW(obj,  "CurrentHorizontalResolution");
            g.yResolution   = _HW::WMISession::GetDW(obj,  "CurrentVerticalResolution");
            g.status        = _HW::WMISession::GetStr(obj, "Status");
            g.pnpDeviceId   = _HW::WMISession::GetStr(obj, "PNPDeviceID");
            result.push_back(g);
        });
        return result;
    }

    /// Get primary GPU name
    inline std::string GetName() {
        auto gpus = GetAll();
        return gpus.empty() ? "" : gpus[0].name;
    }

    /// Get primary GPU VRAM in GB
    inline double GetVRAM_GB() {
        auto gpus = GetAll();
        if (gpus.empty()) return 0.0;
        return static_cast<double>(gpus[0].vramBytes) / (1024.0 * 1024 * 1024);
    }

    /// Get current display resolution and refresh rate
    inline std::tuple<DWORD,DWORD,DWORD> GetCurrentMode() {
        auto gpus = GetAll();
        if (gpus.empty()) return {0,0,0};
        return { gpus[0].xResolution, gpus[0].yResolution, gpus[0].currentHz };
    }

} // namespace GPU

// ============================================================
//  SECTION H3 — RAM Information
// ============================================================
namespace RAM {

    struct RAMStick {
        std::string manufacturer;
        std::string partNumber;
        std::string serialNumber;
        uint64_t    capacityBytes = 0;
        DWORD       speedMHz      = 0;
        DWORD       memoryType    = 0;  // 20=DDR, 21=DDR2, 24=DDR3, 26=DDR4, 34=DDR5
        DWORD       formFactor    = 0;  // 8=DIMM, 12=SO-DIMM
        std::string bankLabel;
        std::string deviceLocator;
    };

    /// Get info on each physical RAM stick
    inline std::vector<RAMStick> GetSticks() {
        std::vector<RAMStick> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_PhysicalMemory", [&](IWbemClassObject* obj) {
            RAMStick s;
            s.manufacturer  = _HW::WMISession::GetStr(obj, "Manufacturer");
            s.partNumber    = _HW::WMISession::GetStr(obj, "PartNumber");
            s.serialNumber  = _HW::WMISession::GetStr(obj, "SerialNumber");
            s.capacityBytes = _HW::WMISession::GetU64(obj, "Capacity");
            s.speedMHz      = _HW::WMISession::GetDW(obj,  "Speed");
            s.memoryType    = _HW::WMISession::GetDW(obj,  "SMBIOSMemoryType");
            s.formFactor    = _HW::WMISession::GetDW(obj,  "FormFactor");
            s.bankLabel     = _HW::WMISession::GetStr(obj, "BankLabel");
            s.deviceLocator = _HW::WMISession::GetStr(obj, "DeviceLocator");
            result.push_back(s);
        });
        return result;
    }

    /// Get total installed physical RAM in GB
    inline double GetTotalGB() {
        MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        return ms.ullTotalPhys / (1024.0 * 1024 * 1024);
    }

    /// Get available RAM in GB
    inline double GetAvailableGB() {
        MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        return ms.ullAvailPhys / (1024.0 * 1024 * 1024);
    }

    /// Get RAM usage percentage
    inline double GetUsagePercent() {
        MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        return static_cast<double>(ms.dwMemoryLoad);
    }

    /// Get RAM type as a string (DDR4, DDR5, etc.)
    inline std::string GetTypeString() {
        auto sticks = GetSticks();
        if (sticks.empty()) return "Unknown";
        switch (sticks[0].memoryType) {
            case 20: return "DDR";
            case 21: return "DDR2";
            case 24: return "DDR3";
            case 26: return "DDR4";
            case 34: return "DDR5";
            default: return "Unknown (" + std::to_string(sticks[0].memoryType) + ")";
        }
    }

    /// Get total RAM speed in MHz (from first stick)
    inline DWORD GetSpeedMHz() {
        auto sticks = GetSticks();
        return sticks.empty() ? 0 : sticks[0].speedMHz;
    }

} // namespace RAM

// ============================================================
//  SECTION H4 — Disk / Storage Information
// ============================================================
namespace Disk {

    struct DiskInfo {
        std::string model;
        std::string serialNumber;
        std::string firmwareRevision;
        std::string interfaceType;   // "IDE", "SCSI", "USB", "NVMe"
        std::string mediaType;       // "Fixed hard disk media", "Removable Media"
        uint64_t    sizeBytes    = 0;
        DWORD       partitions   = 0;
        DWORD       index        = 0;
    };

    struct PartitionInfo {
        std::string name;
        std::string type;
        uint64_t    sizeBytes    = 0;
        uint64_t    startOffset  = 0;
        bool        bootable     = false;
        bool        primaryPartition = false;
        DWORD       diskIndex    = 0;
    };

    /// Get all physical disk drives
    inline std::vector<DiskInfo> GetAll() {
        std::vector<DiskInfo> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_DiskDrive", [&](IWbemClassObject* obj) {
            DiskInfo d;
            d.index            = _HW::WMISession::GetDW(obj,  "Index");
            d.model            = _HW::WMISession::GetStr(obj, "Model");
            d.serialNumber     = _HW::WMISession::GetStr(obj, "SerialNumber");
            d.firmwareRevision = _HW::WMISession::GetStr(obj, "FirmwareRevision");
            d.interfaceType    = _HW::WMISession::GetStr(obj, "InterfaceType");
            d.mediaType        = _HW::WMISession::GetStr(obj, "MediaType");
            d.sizeBytes        = _HW::WMISession::GetU64(obj, "Size");
            d.partitions       = _HW::WMISession::GetDW(obj,  "Partitions");
            result.push_back(d);
        });
        return result;
    }

    /// Get all partitions
    inline std::vector<PartitionInfo> GetPartitions() {
        std::vector<PartitionInfo> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_DiskPartition", [&](IWbemClassObject* obj) {
            PartitionInfo p;
            p.name             = _HW::WMISession::GetStr(obj, "Name");
            p.type             = _HW::WMISession::GetStr(obj, "Type");
            p.sizeBytes        = _HW::WMISession::GetU64(obj, "Size");
            p.startOffset      = _HW::WMISession::GetU64(obj, "StartingOffset");
            p.diskIndex        = _HW::WMISession::GetDW(obj,  "DiskIndex");
            std::string boot   = _HW::WMISession::GetStr(obj, "Bootable");
            std::string prim   = _HW::WMISession::GetStr(obj, "PrimaryPartition");
            p.bootable         = (boot == "true" || boot == "TRUE");
            p.primaryPartition = (prim == "true" || prim == "TRUE");
            result.push_back(p);
        });
        return result;
    }

    /// Get disk read/write speed using PDH counters (bytes/sec)
    inline std::pair<double,double> GetReadWriteSpeed(int diskIndex = 0) {
        PDH_HQUERY query;
        if (PdhOpenQuery(nullptr, 0, &query) != ERROR_SUCCESS) return {0,0};
        std::wstring ri = L"\\PhysicalDisk(" + std::to_wstring(diskIndex) + L")\\Disk Read Bytes/sec";
        std::wstring wi = L"\\PhysicalDisk(" + std::to_wstring(diskIndex) + L")\\Disk Write Bytes/sec";
        PDH_HCOUNTER rc, wc;
        PdhAddEnglishCounterW(query, ri.c_str(), 0, &rc);
        PdhAddEnglishCounterW(query, wi.c_str(), 0, &wc);
        PdhCollectQueryData(query);
        ::Sleep(500);
        PdhCollectQueryData(query);
        PDH_FMT_COUNTERVALUE rv, wv;
        PdhGetFormattedCounterValue(rc, PDH_FMT_DOUBLE, nullptr, &rv);
        PdhGetFormattedCounterValue(wc, PDH_FMT_DOUBLE, nullptr, &wv);
        PdhCloseQuery(query);
        return { rv.doubleValue, wv.doubleValue };
    }

} // namespace Disk

// ============================================================
//  SECTION H5 — Monitor / Display Information
// ============================================================
namespace Monitor {

    struct MonitorInfo {
        std::string name;
        std::string deviceId;
        DWORD       widthPx     = 0;
        DWORD       heightPx    = 0;
        DWORD       refreshHz   = 0;
        DWORD       bitsPerPixel = 0;
        bool        primary     = false;
        RECT        bounds      = {};
    };

    /// Get all connected monitors
    inline std::vector<MonitorInfo> GetAll() {
        std::vector<MonitorInfo> result;
        // Use EnumDisplayMonitors for physical monitor bounds
        struct CallbackData { std::vector<MonitorInfo>* list; };
        CallbackData cb{ &result };
        EnumDisplayMonitors(nullptr, nullptr, [](HMONITOR hMon, HDC, LPRECT, LPARAM lp) -> BOOL {
            auto* data = reinterpret_cast<CallbackData*>(lp);
            MONITORINFOEXW mi{}; mi.cbSize = sizeof(mi);
            GetMonitorInfoW(hMon, &mi);
            MonitorInfo m;
            m.name    = Str::ToNarrow(mi.szDevice);
            m.bounds  = mi.rcMonitor;
            m.primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
            // Get display settings
            DEVMODEW dm{}; dm.dmSize = sizeof(dm);
            if (EnumDisplaySettingsW(mi.szDevice, ENUM_CURRENT_SETTINGS, &dm)) {
                m.widthPx      = dm.dmPelsWidth;
                m.heightPx     = dm.dmPelsHeight;
                m.refreshHz    = dm.dmDisplayFrequency;
                m.bitsPerPixel = dm.dmBitsPerPel;
            }
            data->list->push_back(m);
            return TRUE;
        }, reinterpret_cast<LPARAM>(&cb));
        return result;
    }

    /// Get primary monitor resolution
    inline std::pair<DWORD,DWORD> GetPrimaryResolution() {
        for (auto& m : GetAll())
            if (m.primary) return { m.widthPx, m.heightPx };
        return { static_cast<DWORD>(GetSystemMetrics(SM_CXSCREEN)),
                 static_cast<DWORD>(GetSystemMetrics(SM_CYSCREEN)) };
    }

    /// Get primary monitor refresh rate in Hz
    inline DWORD GetPrimaryRefreshHz() {
        for (auto& m : GetAll())
            if (m.primary) return m.refreshHz;
        return 0;
    }

    /// Get DPI of primary monitor
    inline UINT GetDPI() {
        HDC hdc = GetDC(nullptr);
        UINT dpi = static_cast<UINT>(GetDeviceCaps(hdc, LOGPIXELSX));
        ReleaseDC(nullptr, hdc);
        return dpi;
    }

    /// Get DPI scale factor (1.0 = 100%, 1.25 = 125%, etc.)
    inline double GetScaleFactor() {
        return GetDPI() / 96.0;
    }

    /// Get total virtual desktop size (spanning all monitors)
    inline std::pair<int,int> GetVirtualDesktopSize() {
        return { GetSystemMetrics(SM_CXVIRTUALSCREEN),
                 GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    }

} // namespace Monitor

// ============================================================
//  SECTION H6 — Network Adapter Information
// ============================================================
namespace NetInfo {

    struct AdapterInfo {
        std::string name;
        std::string description;
        std::string macAddress;
        std::string ipv4;
        std::string ipv6;
        std::string subnetMask;
        std::string gateway;
        std::string dnsPrimary;
        std::string dnsSecondary;
        uint64_t    speedBps    = 0;
        bool        connected   = false;
        bool        dhcpEnabled = false;
        std::string adapterType;
    };

    /// Get all network adapters with full info
    inline std::vector<AdapterInfo> GetAll() {
        std::vector<AdapterInfo> result;

        // Use GetAdaptersAddresses — it has DNS, IPv4, IPv6, gateway all in one
        ULONG bufSize = 15000;
        std::vector<BYTE> buf(bufSize);
        PIP_ADAPTER_ADDRESSES pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        ULONG ret = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
            nullptr, pAddrs, &bufSize);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            buf.resize(bufSize);
            pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
            ret = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                nullptr, pAddrs, &bufSize);
        }
        if (ret != NO_ERROR) return result;

        for (auto* p = pAddrs; p; p = p->Next) {
            AdapterInfo a;
            a.name        = Str::ToNarrow(p->FriendlyName);
            a.description = Str::ToNarrow(p->Description);
            a.dhcpEnabled = (p->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
            a.connected   = (p->OperStatus == IfOperStatusUp);
            a.speedBps    = p->TransmitLinkSpeed;

            // Adapter type string
            switch (p->IfType) {
                case IF_TYPE_ETHERNET_CSMACD: a.adapterType = "Ethernet"; break;
                case IF_TYPE_IEEE80211:        a.adapterType = "Wi-Fi";    break;
                case IF_TYPE_SOFTWARE_LOOPBACK:a.adapterType = "Loopback"; break;
                case IF_TYPE_TUNNEL:           a.adapterType = "Tunnel";   break;
                default:                       a.adapterType = "Other";    break;
            }

            // MAC address
            if (p->PhysicalAddressLength >= 6) {
                char mac[18] = {};
                std::snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    p->PhysicalAddress[0], p->PhysicalAddress[1],
                    p->PhysicalAddress[2], p->PhysicalAddress[3],
                    p->PhysicalAddress[4], p->PhysicalAddress[5]);
                a.macAddress = mac;
            }

            // IPv4 and IPv6 addresses
            for (auto* ua = p->FirstUnicastAddress; ua; ua = ua->Next) {
                char ipBuf[64] = {};
                DWORD ipBufLen = sizeof(ipBuf);
                WSAAddressToStringA(ua->Address.lpSockaddr,
                    ua->Address.iSockaddrLength, nullptr, ipBuf, &ipBufLen);
                if (ua->Address.lpSockaddr->sa_family == AF_INET)
                    a.ipv4 = ipBuf;
                else if (ua->Address.lpSockaddr->sa_family == AF_INET6 && a.ipv6.empty())
                    a.ipv6 = ipBuf;
            }

            // Gateway
            for (auto* gw = p->FirstGatewayAddress; gw; gw = gw->Next) {
                char gwBuf[64] = {};
                DWORD gwLen = sizeof(gwBuf);
                if (WSAAddressToStringA(gw->Address.lpSockaddr,
                    gw->Address.iSockaddrLength, nullptr, gwBuf, &gwLen) == 0) {
                    a.gateway = gwBuf;
                    break; // just the first gateway
                }
            }

            // DNS servers
            bool firstDns = true;
            for (auto* dns = p->FirstDnsServerAddress; dns; dns = dns->Next) {
                char dnsBuf[64] = {};
                DWORD dnsLen = sizeof(dnsBuf);
                if (WSAAddressToStringA(dns->Address.lpSockaddr,
                    dns->Address.iSockaddrLength, nullptr, dnsBuf, &dnsLen) == 0) {
                    if (firstDns) { a.dnsPrimary   = dnsBuf; firstDns = false; }
                    else          { a.dnsSecondary  = dnsBuf; break; }
                }
            }

            result.push_back(a);
        }
        return result;
    }

    /// Get network throughput using PDH (bytes/sec in and out)
    inline std::pair<double,double> GetThroughput(const std::string& adapterName = "_Total") {
        PDH_HQUERY query;
        if (PdhOpenQuery(nullptr, 0, &query) != ERROR_SUCCESS) return {0,0};
        std::wstring name = Str::ToWide(adapterName);
        std::wstring ri = L"\\Network Interface(" + name + L")\\Bytes Received/sec";
        std::wstring si = L"\\Network Interface(" + name + L")\\Bytes Sent/sec";
        PDH_HCOUNTER rc, sc;
        PdhAddEnglishCounterW(query, ri.c_str(), 0, &rc);
        PdhAddEnglishCounterW(query, si.c_str(), 0, &sc);
        PdhCollectQueryData(query);
        ::Sleep(500);
        PdhCollectQueryData(query);
        PDH_FMT_COUNTERVALUE rv, sv;
        PdhGetFormattedCounterValue(rc, PDH_FMT_DOUBLE, nullptr, &rv);
        PdhGetFormattedCounterValue(sc, PDH_FMT_DOUBLE, nullptr, &sv);
        PdhCloseQuery(query);
        return { rv.doubleValue, sv.doubleValue };
    }

    /// Ping a host, returns round-trip time in ms or -1 on failure
    inline int Ping(const std::string& host, DWORD timeoutMs = 1000) {
        auto result = Process::RunCapture("ping -n 1 -w " + std::to_string(timeoutMs) + " " + host);
        if (!result) return -1;
        auto pos = result->find("Average = ");
        if (pos == std::string::npos) return -1;
        try { return std::stoi(result->substr(pos + 10)); } catch (...) { return -1; }
    }

} // namespace NetInfo

// ============================================================
//  SECTION H7 — USB & Connected Devices
// ============================================================
namespace Devices {

    struct USBDevice {
        std::string name;
        std::string deviceId;
        std::string manufacturer;
        std::string description;
        std::string service;
        std::string status;
    };

    struct PrinterInfo {
        std::string name;
        std::string portName;
        std::string driverName;
        std::string status;
        bool        isDefault   = false;
        bool        isNetwork   = false;
    };

    /// Get all connected USB devices
    inline std::vector<USBDevice> GetUSBDevices() {
        std::vector<USBDevice> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_USBControllerDevice", [&](IWbemClassObject* obj) {
            // Get the dependent device path
            std::string dep = _HW::WMISession::GetStr(obj, "Dependent");
            if (dep.empty()) return;
            // Extract PNP device ID from the path
            auto pos = dep.find("DeviceID=\"");
            if (pos == std::string::npos) return;
            std::string devId = dep.substr(pos + 10);
            if (!devId.empty() && devId.back() == '"') devId.pop_back();
            // Escape backslashes for WQL
            std::string escaped = Str::ReplaceAll(devId, "\\", "\\\\");
            USBDevice dev;
            dev.deviceId = devId;
            _HW::WMISession wmi2;
            wmi2.Query("SELECT * FROM Win32_PnPEntity WHERE DeviceID='" + escaped + "'",
                [&](IWbemClassObject* o) {
                    dev.name         = _HW::WMISession::GetStr(o, "Name");
                    dev.manufacturer = _HW::WMISession::GetStr(o, "Manufacturer");
                    dev.description  = _HW::WMISession::GetStr(o, "Description");
                    dev.service      = _HW::WMISession::GetStr(o, "Service");
                    dev.status       = _HW::WMISession::GetStr(o, "Status");
                });
            if (!dev.name.empty()) result.push_back(dev);
        });
        return result;
    }

    /// Get all installed printers
    inline std::vector<PrinterInfo> GetPrinters() {
        std::vector<PrinterInfo> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_Printer", [&](IWbemClassObject* obj) {
            PrinterInfo p;
            p.name       = _HW::WMISession::GetStr(obj, "Name");
            p.portName   = _HW::WMISession::GetStr(obj, "PortName");
            p.driverName = _HW::WMISession::GetStr(obj, "DriverName");
            p.status     = _HW::WMISession::GetStr(obj, "Status");
            std::string def = _HW::WMISession::GetStr(obj, "Default");
            std::string net = _HW::WMISession::GetStr(obj, "Network");
            p.isDefault  = (def == "true" || def == "TRUE");
            p.isNetwork  = (net == "true" || net == "TRUE");
            result.push_back(p);
        });
        return result;
    }

    /// Get all PnP devices (generic)
    inline std::vector<std::string> GetAllPnPDeviceNames() {
        std::vector<std::string> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT Name FROM Win32_PnPEntity WHERE Status='OK'",
            [&](IWbemClassObject* obj) {
                auto name = _HW::WMISession::GetStr(obj, "Name");
                if (!name.empty()) result.push_back(name);
            });
        return result;
    }

} // namespace Devices

// ============================================================
//  SECTION H8 — Battery Information
// ============================================================
namespace Battery {

    struct BatteryInfo {
        int         percent         = -1;
        bool        isCharging      = false;
        bool        hasBattery      = false;
        DWORD       estimatedMins   = 0;   // 0 if charging/unknown
        std::string designCapacity;
        std::string fullChargeCapacity;
        std::string cycleCount;
        std::string chemistry;             // "Lithium Ion", etc.
        std::string manufacturer;
        std::string name;
    };

    /// Get full battery information
    inline BatteryInfo GetInfo() {
        BatteryInfo info;
        SYSTEM_POWER_STATUS sps{};
        GetSystemPowerStatus(&sps);
        if (sps.BatteryLifePercent == 255) { info.hasBattery = false; return info; }
        info.hasBattery    = true;
        info.percent       = sps.BatteryLifePercent;
        info.isCharging    = (sps.ACLineStatus == 1);
        info.estimatedMins = (sps.BatteryLifeTime != 0xFFFFFFFF)
                             ? sps.BatteryLifeTime / 60 : 0;
        // Get extended info via WMI
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_Battery", [&](IWbemClassObject* obj) {
            info.name               = _HW::WMISession::GetStr(obj, "Name");
            info.manufacturer       = _HW::WMISession::GetStr(obj, "Manufacturer");
            info.chemistry          = _HW::WMISession::GetStr(obj, "Chemistry");
            info.designCapacity     = _HW::WMISession::GetStr(obj, "DesignCapacity");
            info.fullChargeCapacity = _HW::WMISession::GetStr(obj, "FullChargeCapacity");
        });
        return info;
    }

    inline int  GetPercent()    { return GetInfo().percent;    }
    inline bool IsCharging()    { return GetInfo().isCharging; }
    inline bool HasBattery()    { return GetInfo().hasBattery; }

} // namespace Battery

// ============================================================
//  SECTION H9 — Installed Software
// ============================================================
namespace Software {

    struct InstalledApp {
        std::string name;
        std::string version;
        std::string publisher;
        std::string installDate;
        std::string installLocation;
        std::string uninstallString;
    };

    /// Get all installed applications (reads from registry, faster than WMI)
    inline std::vector<InstalledApp> GetInstalled() {
        std::vector<InstalledApp> result;
        auto readFrom = [&](HKEY root, const std::string& subkey) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
                return;
            wchar_t name[256]; DWORD nameSz = 256; DWORD idx = 0;
            while (RegEnumKeyExW(hk, idx++, name, &nameSz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                nameSz = 256;
                HKEY appKey = nullptr;
                std::wstring appPath = Str::ToWide(subkey) + L"\\" + name;
                if (RegOpenKeyExW(root, appPath.c_str(), 0, KEY_READ, &appKey) != ERROR_SUCCESS) continue;
                auto readVal = [&](const std::string& val) -> std::string {
                    wchar_t buf[1024] = {}; DWORD sz = sizeof(buf);
                    if (RegQueryValueExW(appKey, Str::ToWide(val).c_str(), nullptr, nullptr,
                        reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS)
                        return Str::ToNarrow(buf);
                    return {};
                };
                InstalledApp app;
                app.name             = readVal("DisplayName");
                app.version          = readVal("DisplayVersion");
                app.publisher        = readVal("Publisher");
                app.installDate      = readVal("InstallDate");
                app.installLocation  = readVal("InstallLocation");
                app.uninstallString  = readVal("UninstallString");
                if (!app.name.empty()) result.push_back(app);
                RegCloseKey(appKey);
            }
            RegCloseKey(hk);
        };
        const std::string key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        const std::string key32 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        readFrom(HKEY_LOCAL_MACHINE, key);
        readFrom(HKEY_LOCAL_MACHINE, key32);
        readFrom(HKEY_CURRENT_USER,  key);
        return result;
    }

    /// Check if an application is installed by partial name match
    inline bool IsInstalled(const std::string& partialName) {
        std::string lower = partialName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (auto& app : GetInstalled()) {
            std::string n = app.name;
            std::transform(n.begin(), n.end(), n.begin(), ::tolower);
            if (n.find(lower) != std::string::npos) return true;
        }
        return false;
    }

} // namespace Software

// ============================================================
//  SECTION H10 — Running Processes with Resource Usage
// ============================================================
namespace ProcessInfo {

    struct ProcessStats {
        DWORD       pid          = 0;
        std::string name;
        std::string executablePath;
        SIZE_T      workingSetMB = 0;   // RAM usage in MB
        SIZE_T      privateBytesMB = 0;
        double      cpuPercent   = 0.0;
        DWORD       threadCount  = 0;
        DWORD       handleCount  = 0;
        std::string user;
    };

    /// Get stats for all running processes
    inline std::vector<ProcessStats> GetAll() {
        std::vector<ProcessStats> result;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_Process", [&](IWbemClassObject* obj) {
            ProcessStats s;
            s.pid              = _HW::WMISession::GetDW(obj, "ProcessId");
            s.name             = _HW::WMISession::GetStr(obj, "Name");
            s.executablePath   = _HW::WMISession::GetStr(obj, "ExecutablePath");
            s.threadCount      = _HW::WMISession::GetDW(obj, "ThreadCount");
            s.handleCount      = _HW::WMISession::GetDW(obj, "HandleCount");
            uint64_t ws        = _HW::WMISession::GetU64(obj, "WorkingSetSize");
            uint64_t pb        = _HW::WMISession::GetU64(obj, "PrivatePageCount");
            s.workingSetMB     = static_cast<SIZE_T>(ws   / (1024 * 1024));
            s.privateBytesMB   = static_cast<SIZE_T>(pb   / (1024 * 1024));
            result.push_back(s);
        });
        return result;
    }

    /// Get stats for a single process by PID
    inline std::optional<ProcessStats> GetByPID(DWORD pid) {
        for (auto& p : GetAll())
            if (p.pid == pid) return p;
        return std::nullopt;
    }

    /// Get top N processes by RAM usage
    inline std::vector<ProcessStats> GetTopByRAM(int n = 10) {
        auto all = GetAll();
        std::sort(all.begin(), all.end(), [](const ProcessStats& a, const ProcessStats& b) {
            return a.workingSetMB > b.workingSetMB;
        });
        if (static_cast<int>(all.size()) > n) all.resize(n);
        return all;
    }

} // namespace ProcessInfo

// ============================================================
//  SECTION H11 — System Temperatures & Sensors
// ============================================================
namespace Sensors {

    struct ThermalZone {
        std::string name;
        double      temperatureCelsius = -1.0;
    };

    /// Get all thermal zones (requires Admin on most hardware)
    inline std::vector<ThermalZone> GetThermalZones() {
        std::vector<ThermalZone> result;
        _HW::WMISession wmi;
        // Switch to root\WMI
        if (wmi.pSvc) wmi.pSvc->Release(); wmi.pSvc = nullptr;
        if (wmi.pLoc)
            wmi.pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"),
                nullptr, nullptr, nullptr, 0, nullptr, nullptr, &wmi.pSvc);
        if (!wmi.pSvc) return result;
        wmi.Query("SELECT * FROM MSAcpi_ThermalZoneTemperature", [&](IWbemClassObject* obj) {
            ThermalZone tz;
            tz.name = _HW::WMISession::GetStr(obj, "InstanceName");
            DWORD raw = _HW::WMISession::GetDW(obj, "CurrentTemperature");
            if (raw > 0) tz.temperatureCelsius = (raw / 10.0) - 273.15;
            result.push_back(tz);
        });
        return result;
    }

    /// Get system uptime in seconds
    inline uint64_t GetUptimeSeconds() {
        return GetTickCount64() / 1000;
    }

    /// Get system uptime as a formatted string e.g. "3d 14h 22m"
    inline std::string GetUptimeString() {
        uint64_t s = GetUptimeSeconds();
        uint64_t d = s / 86400; s %= 86400;
        uint64_t h = s / 3600;  s %= 3600;
        uint64_t m = s / 60;
        std::string result;
        if (d > 0) result += std::to_string(d) + "d ";
        result += std::to_string(h) + "h " + std::to_string(m) + "m";
        return result;
    }

    /// Get current page file usage
    inline std::pair<uint64_t,uint64_t> GetPageFileUsageMB() {
        MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        uint64_t total = (ms.ullTotalPageFile - ms.ullTotalPhys) / (1024*1024);
        uint64_t used  = total - ms.ullAvailPageFile / (1024*1024);
        return { used, total };
    }

} // namespace Sensors

// ============================================================
//  SECTION H12 — BIOS & Motherboard
// ============================================================
namespace Board {

    struct BIOSInfo {
        std::string manufacturer;
        std::string version;
        std::string releaseDate;
        std::string serialNumber;
        bool        isUEFI = false;
    };

    struct MotherboardInfo {
        std::string manufacturer;
        std::string product;
        std::string version;
        std::string serialNumber;
    };

    inline BIOSInfo GetBIOS() {
        BIOSInfo info;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_BIOS", [&](IWbemClassObject* obj) {
            info.manufacturer = _HW::WMISession::GetStr(obj, "Manufacturer");
            info.version      = _HW::WMISession::GetStr(obj, "SMBIOSBIOSVersion");
            info.releaseDate  = _HW::WMISession::GetStr(obj, "ReleaseDate");
            info.serialNumber = _HW::WMISession::GetStr(obj, "SerialNumber");
            std::string caps  = _HW::WMISession::GetStr(obj, "BIOSCharacteristics");
            info.isUEFI       = caps.find("19") != std::string::npos; // UEFI capability bit
        });
        return info;
    }

    inline MotherboardInfo GetMotherboard() {
        MotherboardInfo info;
        _HW::WMISession wmi;
        wmi.Query("SELECT * FROM Win32_BaseBoard", [&](IWbemClassObject* obj) {
            info.manufacturer = _HW::WMISession::GetStr(obj, "Manufacturer");
            info.product      = _HW::WMISession::GetStr(obj, "Product");
            info.version      = _HW::WMISession::GetStr(obj, "Version");
            info.serialNumber = _HW::WMISession::GetStr(obj, "SerialNumber");
        });
        return info;
    }

    /// Get Windows product key / serial
    inline std::string GetWindowsSerial() {
        _HW::WMISession wmi;
        std::string serial;
        wmi.Query("SELECT SerialNumber FROM Win32_OperatingSystem", [&](IWbemClassObject* obj) {
            serial = _HW::WMISession::GetStr(obj, "SerialNumber");
        });
        return serial;
    }

    /// Get machine UUID (unique per motherboard)
    inline std::string GetMachineUUID() {
        _HW::WMISession wmi;
        std::string uuid;
        wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", [&](IWbemClassObject* obj) {
            uuid = _HW::WMISession::GetStr(obj, "UUID");
        });
        return uuid;
    }

} // namespace Board

} // namespace WinUtils

#endif // WIN_HARDWARE_HPP

// ============================================================
//  QUICK REFERENCE — WinHardware.hpp
// ============================================================
//
//  CPU::       GetInfo, GetName, GetCoreCount, GetLogicalCount,
//              GetMaxClockMHz, GetUsagePercent, GetPerCoreUsage,
//              GetTemperatureCelsius
//
//  GPU::       GetAll, GetName, GetVRAM_GB, GetCurrentMode
//
//  RAM::       GetSticks, GetTotalGB, GetAvailableGB,
//              GetUsagePercent, GetTypeString, GetSpeedMHz
//
//  Disk::      GetAll, GetPartitions, GetReadWriteSpeed
//
//  Monitor::   GetAll, GetPrimaryResolution, GetPrimaryRefreshHz,
//              GetDPI, GetScaleFactor, GetVirtualDesktopSize
//
//  NetInfo::   GetAll, GetThroughput, Ping
//
//  Devices::   GetUSBDevices, GetPrinters, GetAllPnPDeviceNames
//
//  Battery::   GetInfo, GetPercent, IsCharging, HasBattery
//
//  Software::  GetInstalled, IsInstalled
//
//  ProcessInfo:: GetAll, GetByPID, GetTopByRAM
//
//  Sensors::   GetThermalZones, GetUptimeSeconds, GetUptimeString,
//              GetPageFileUsageMB
//
//  Board::     GetBIOS, GetMotherboard, GetWindowsSerial, GetMachineUUID
//
// ============================================================