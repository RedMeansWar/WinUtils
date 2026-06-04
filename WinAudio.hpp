/*
 * ============================================================================
 * winaudio.hpp
 * Part of the WinUtils project — Windows Audio utility namespace
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
 * This file uses WASAPI (Windows Audio Session API) and the Windows Service
 * Control Manager to enumerate audio devices, query their properties, and
 * control the Windows Audio service. Restarting the audio service briefly
 * interrupts all audio output system-wide.
 *
 * The author accepts no responsibility for damages arising from use or misuse.
 *
 * ============================================================================
 *
 * Requires : Windows Vista or later (WASAPI), C++17 or later, winutils.hpp
 * Qt compat: Define WINUTILS_AUDIO_QT before including to enable Q_GADGET
 *            registration and Q_PROPERTY macros on AudioDevice. Requires Qt6
 *            headers to be available on the include path.
 * Reference : See README.md for full documentation
 *
 * ============================================================================
 *
 * Pragma links (auto-linked):
 *   ole32, oleaut32, uuid, advapi32
 *
 * ============================================================================
*/

#pragma once
#ifndef WINUTILS_AUDIO_HPP
#define WINUTILSAUDIO_HPP

#include "winutils.hpp"

// ---- WASAPI / MMDevice Headers ----
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#include <audioclient.h>
#include <functiondiscoverykeys_devpkey.h>
#include <propsys.h>
#include <propvarutil.h>
#include <audiopolicy.h>
#include <devicetopology.h>

// Have these here if we get errors regarding subform GUIDs later.
#include <ks.h>
#include <ksmedia.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "advapi32.lib")

// Manually define the IconPath property key structure if the SDK headers miss it
#ifndef PKEY_Device_IconPath
#include <initguid.h>
DEFINE_PROPERTYKEY(PKEY_Device_IconPath, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 2);
#endif

// ---- Optional Qt compatibility ----
// Define WINUTILS_AUDIO_QT before including this header to enable
// Q_GADGET, Q_PROPERTY, and qRegisterMetaType support on AudioDevice.
#ifdef WINUTILS_AUDIO_QT
#  include <QObject>
#  include <QString>
#  include <QList>
#  include <QMetaType>
#  define _WINAUDIO_STRING  QString
#  define _WINAUDIO_TOSTR(w) QString::fromStdWString(w)
#  define _WINAUDIO_GADGET  Q_GADGET
#  define _WINAUDIO_PROP(type, name) Q_PROPERTY(type name MEMBER name)
#else
#  define _WINAUDIO_STRING  std::string
#  define _WINAUDIO_TOSTR(w) WinUtils::Str::ToNarrow(w)
#  define _WINAUDIO_GADGET
#  define _WINAUDIO_PROP(type, name)
#endif

namespace WinUtils {
namespace Audio {
    
    // ============================================================
//  Internal WASAPI helpers
// ============================================================
namespace _Detail {
 
    /// RAII COM initializer — safe to nest; uses COINIT_APARTMENTTHREADED.
    struct ComGuard {
        bool initialized = false;
        ComGuard() {
            HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            initialized = SUCCEEDED(hr) || (hr == RPC_E_CHANGED_MODE);
        }
        ~ComGuard() { if (initialized) CoUninitialize(); }
        ComGuard(const ComGuard&) = delete;
        ComGuard& operator=(const ComGuard&) = delete;
    };
 
    /// Read a PKEY_Device_* string property from a property store.
    inline std::wstring ReadPropStr(IPropertyStore* store, const PROPERTYKEY& key) {
        if (!store) return {};
        PROPVARIANT pv;
        PropVariantInit(&pv);
        if (FAILED(store->GetValue(key, &pv))) return {};
        std::wstring result;
        if (pv.vt == VT_LPWSTR && pv.pwszVal)
            result = pv.pwszVal;
        PropVariantClear(&pv);
        return result;
    }
 
    /// Read a PKEY_Device_* DWORD property from a property store.
    inline DWORD ReadPropDW(IPropertyStore* store, const PROPERTYKEY& key) {
        if (!store) return 0;
        PROPVARIANT pv;
        PropVariantInit(&pv);
        if (FAILED(store->GetValue(key, &pv))) { PropVariantClear(&pv); return 0; }
        DWORD result = 0;
        if (pv.vt == VT_UI4) result = pv.ulVal;
        PropVariantClear(&pv);
        return result;
    }
 
    /// Create the MMDeviceEnumerator.
    inline IMMDeviceEnumerator* CreateEnumerator() {
        IMMDeviceEnumerator* pEnum = nullptr;
        CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr,
            CLSCTX_ALL, __uuidof(IMMDeviceEnumerator),
            reinterpret_cast<void**>(&pEnum));
        return pEnum;
    }
 
} // namespace _Detail
 
// ============================================================
//  AudioDeviceType — render (output) or capture (input)
// ============================================================

///  Specifies the data flow direction or usage filter for a Windows audio endpoint.
///  This enumeration categorizes audio hardware into distinct roles, matching the native 
///  Windows Multimedia Device (MMDevice) architecture data flows.
enum class AudioDeviceType {
    Render,   ///< Output — speakers, headphones, HDMI audio, etc.
    Capture,  ///< Input  — microphones, line-in, etc.
    All       ///< Both — used as a filter parameter only
};
 
// ============================================================
//  AudioDevice — rich audio endpoint descriptor
//
//  Qt compatibility:
//    Define WINUTILS_AUDIO_QT before including this header.
//    All string fields become QString; the struct gains Q_GADGET.
//    Call qRegisterMetaType<WinUtils::Audio::AudioDevice>() once in
//    main() or your plugin loader to make it usable in QML / signals.
// ============================================================

/// A rich audio endpoint descriptor.
/// This structure maps native WASAPI device attributes, format configurations, 
/// and deep Windows registry effects keys into a unified data container.
struct AudioDevice {
    _WINAUDIO_GADGET
 
    // ---- Identity ----
    _WINAUDIO_PROP(_WINAUDIO_STRING, id)
    _WINAUDIO_STRING id;                ///< WASAPI endpoint ID (e.g. "{0.0.0.00000000}.{...}")
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, friendlyName)
    _WINAUDIO_STRING friendlyName;      ///< Human-readable name — "Speakers (Realtek HD Audio)"
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, description)
    _WINAUDIO_STRING description;       ///< Device description — "Speakers"
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, interfaceName)
    _WINAUDIO_STRING interfaceName;     ///< Audio adapter name — "Realtek HD Audio"
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, iconPath)
    _WINAUDIO_STRING iconPath;          ///< Path to the device icon (may include comma-index)
 
    // ---- State ----
    _WINAUDIO_PROP(bool, isDefault)
    bool isDefault = false;             ///< True if this is the system default for its data flow
 
    _WINAUDIO_PROP(bool, isDefaultComm)
    bool isDefaultComm = false;         ///< True if this is the default communications device
 
    _WINAUDIO_PROP(bool, isActive)
    bool isActive = false;              ///< True if the device is plugged in and enabled
 
    // ---- Format ----
    _WINAUDIO_PROP(DWORD, channels)
    DWORD channels = 0;                 ///< Number of audio channels (2 = stereo, 6 = 5.1, etc.)
 
    _WINAUDIO_PROP(DWORD, sampleRate)
    DWORD sampleRate = 0;               ///< Native sample rate in Hz (e.g. 44100, 48000, 192000)
 
    _WINAUDIO_PROP(DWORD, bitsPerSample)
    DWORD bitsPerSample = 0;            ///< Bit depth (16, 24, 32)
 
    _WINAUDIO_PROP(DWORD, blockAlign)
    DWORD blockAlign = 0;               ///< Frame size in bytes (channels * bitsPerSample / 8)
 
    _WINAUDIO_PROP(DWORD, avgBytesPerSec)
    DWORD avgBytesPerSec = 0;           ///< Average data rate (sampleRate * blockAlign)
 
    _WINAUDIO_PROP(DWORD, formatTag)
    DWORD formatTag = 0;                ///< WAVE_FORMAT_PCM (1) or WAVE_FORMAT_IEEE_FLOAT (3)
 
    // ---- Enhancements ----
    _WINAUDIO_PROP(bool, supportsEnhancements)
    bool supportsEnhancements = false;  ///< True if APO (Audio Processing Object) chain is present
 
    // ---- Routing ----
    _WINAUDIO_PROP(AudioDeviceType, deviceType)
    AudioDeviceType deviceType = AudioDeviceType::Render;  ///< Render or Capture

    _WINAUDIO_PROP(_WINAUDIO_STRING, jackType)
    _WINAUDIO_STRING jackType;          ///< Physical connection type, e.g. "3.5mm Jack", "USB", "HDMI", "Optical"
 
    _WINAUDIO_PROP(DWORD, jackColor)
    DWORD jackColor = 0;                ///< RGB color hex code of the physical connection jack (if reported by driver)
 
    _WINAUDIO_PROP(bool, isSpatialAudioEnabled)
    bool isSpatialAudioEnabled = false; ///< True if Windows Sonic, Dolby Atmos, or DTS Headphone:X is currently active
 
    // ---- Volume ----
    _WINAUDIO_PROP(float, masterVolume)
    float masterVolume = 0.0f;          ///< Current master volume scalar [0.0 – 1.0]
 
    _WINAUDIO_PROP(bool, isMuted)
    bool isMuted = false;               ///< True if the endpoint is currently muted

    // ---- Hardware Properties ----
    _WINAUDIO_PROP(_WINAUDIO_STRING, hardwareId)
    _WINAUDIO_STRING hardwareId;        ///< Hardware enumeration ID string, e.g. "HDAUDIO\FUNC_01&VEN_10EC&DEV_0892"
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, driverVersion)
    _WINAUDIO_STRING driverVersion;     ///< Installed system driver version string for the device adapter
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, driverProvider)
    _WINAUDIO_STRING driverProvider;    ///< Vendor who wrote the device driver, e.g. "Realtek", "Microsoft", "Intel"

    // ---- Hardware & Driver Profiles ----
    _WINAUDIO_PROP(_WINAUDIO_STRING, hardwareId)
    _WINAUDIO_STRING hardwareId;        ///< Hardware enumeration PnP ID string, e.g. "HDAUDIO\FUNC_01&VEN_10EC&DEV_0892"
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, driverVersion)
    _WINAUDIO_STRING driverVersion;     ///< Installed system driver version string for the device controller adapter
 
    _WINAUDIO_PROP(_WINAUDIO_STRING, driverProvider)
    _WINAUDIO_STRING driverProvider;    ///< Vendor who authored the device driver, e.g. "Realtek", "Microsoft", "Intel"

    _WINAUDIO_PROP(bool, isSpatialAudioEnabled)
    bool isSpatialAudioEnabled = false; ///< True if an active spatial sound provider (Sonic, Atmos, DTS) is currently active
 
    // ---- Helpers ----
 
    /// Returns the sample rate formatted as a human-readable string, e.g. "48 kHz".
    std::string SampleRateStr() const {
        if (sampleRate == 0) return "Unknown";
        if (sampleRate % 1000 == 0) return std::to_string(sampleRate / 1000) + " kHz";
        return std::to_string(sampleRate) + " Hz";
    }
 
    /// Returns the format tag as a string ("PCM", "IEEE Float", or the raw tag number).
    std::string FormatTagStr() const {
        switch (formatTag) {
            case WAVE_FORMAT_PCM:        return "PCM";
            case WAVE_FORMAT_IEEE_FLOAT: return "IEEE Float";
            default:                     return "Format " + std::to_string(formatTag);
        }
    }
 
    /// Returns a short summary, e.g. "48 kHz / 24-bit / 2ch".
    std::string FormatSummary() const {
        return SampleRateStr() + " / "
             + std::to_string(bitsPerSample) + "-bit / "
             + std::to_string(channels) + "ch";
    }
};
 
// ============================================================
//  Internal — populate a single AudioDevice from an IMMDevice
// ============================================================
namespace _Detail {
    /// Internal helper function to populate an AudioDevice struct from an active IMMDevice pointer.
    /// Extracts core WASAPI metadata, matches device defaults/roles, and queries underlying registry values.
    /// @param pDevice Pointer to the native Windows MMDevice endpoint interface.
    /// @param defaultRenderId The current system default multimedia playback endpoint ID.
    /// @param defaultCaptureId The current system default multimedia recording endpoint ID.
    /// @param defaultCommRenderId The current system default voice communications playback endpoint ID.
    /// @param defaultCommCaptureId The current system default voice communications recording endpoint ID.
    /// @param flow Explicit data flow category direction (Render or Capture) assigned to this device context.
    /// @return A completely initialized AudioDevice struct populated with hardware and registry properties.
    inline AudioDevice PopulateDevice(IMMDevice* pDevice,
                                       const std::wstring& defaultRenderId,
                                       const std::wstring& defaultCaptureId,
                                       const std::wstring& defaultCommRenderId,
                                       const std::wstring& defaultCommCaptureId,
                                       AudioDeviceType flow)
    {
        AudioDevice dev;
        dev.deviceType = flow;
 
        // -- ID --
        LPWSTR pwszId = nullptr;
        if (SUCCEEDED(pDevice->GetId(&pwszId)) && pwszId) {
            std::wstring wid(pwszId);
            dev.id = _WINAUDIO_TOSTR(wid);
            dev.isDefault     = (wid == defaultRenderId  || wid == defaultCaptureId);
            dev.isDefaultComm = (wid == defaultCommRenderId || wid == defaultCommCaptureId);
            CoTaskMemFree(pwszId);
        }
 
        // -- State --
        DWORD state = 0;
        if (SUCCEEDED(pDevice->GetState(&state)))
            dev.isActive = (state == DEVICE_STATE_ACTIVE);
 
        // -- Property store --
        IPropertyStore* pStore = nullptr;
        if (SUCCEEDED(pDevice->OpenPropertyStore(STGM_READ, &pStore))) {
            auto ws = [&](const PROPERTYKEY& k) { return ReadPropStr(pStore, k); };
 
            dev.friendlyName  = _WINAUDIO_TOSTR(ws(PKEY_Device_FriendlyName));
            dev.description   = _WINAUDIO_TOSTR(ws(PKEY_Device_DeviceDesc));
            dev.interfaceName = _WINAUDIO_TOSTR(ws(PKEY_DeviceInterface_FriendlyName));
            dev.iconPath      = _WINAUDIO_TOSTR(ws(PKEY_Device_IconPath));
 
            // -- Native format (PKEY_AudioEngine_DeviceFormat) --
            // This PROPVARIANT holds a WAVEFORMATEX blob.
            PROPVARIANT fmtPv;
            PropVariantInit(&fmtPv);
            if (SUCCEEDED(pStore->GetValue(PKEY_AudioEngine_DeviceFormat, &fmtPv))
                && fmtPv.vt == VT_BLOB && fmtPv.blob.cbSize >= sizeof(WAVEFORMATEX))
            {
                const auto* wfx = reinterpret_cast<const WAVEFORMATEX*>(fmtPv.blob.pBlobData);
                dev.channels       = wfx->nChannels;
                dev.sampleRate     = wfx->nSamplesPerSec;
                dev.bitsPerSample  = wfx->wBitsPerSample;
                dev.blockAlign     = wfx->nBlockAlign;
                dev.avgBytesPerSec = wfx->nAvgBytesPerSec;
                dev.formatTag      = wfx->wFormatTag;
 
                // WAVE_FORMAT_EXTENSIBLE wraps an inner format tag
                if (wfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE
                    && fmtPv.blob.cbSize >= sizeof(WAVEFORMATEXTENSIBLE))
                {
                    const auto* wfex = reinterpret_cast<const WAVEFORMATEXTENSIBLE*>(wfx);
                    // Map SubFormat GUID to a tag for convenience
                    if (IsEqualGUID(wfex->SubFormat, KSDATAFORMAT_SUBTYPE_PCM))
                        dev.formatTag = WAVE_FORMAT_PCM;
                    else if (IsEqualGUID(wfex->SubFormat, KSDATAFORMAT_SUBTYPE_IEEE_FLOAT))
                        dev.formatTag = WAVE_FORMAT_IEEE_FLOAT;
                    dev.bitsPerSample = wfex->Samples.wValidBitsPerSample
                                            ? wfex->Samples.wValidBitsPerSample
                                            : wfx->wBitsPerSample;
                }
            }
            PropVariantClear(&fmtPv);
 
            // -- APO / Enhancement support check --
            // If PKEY_AudioEngine_OEMFormat is present, the driver has an APO chain.
            PROPVARIANT oemPv;
            PropVariantInit(&oemPv);
            dev.supportsEnhancements =
                SUCCEEDED(pStore->GetValue(PKEY_AudioEngine_OEMFormat, &oemPv))
                && oemPv.vt != VT_EMPTY
                && oemPv.blob.cbSize > 0;
            PropVariantClear(&oemPv);
 
            pStore->Release();
        }
 
        // -- Volume / mute --
        IAudioEndpointVolume* pVol = nullptr;
        if (SUCCEEDED(pDevice->Activate(__uuidof(IAudioEndpointVolume),
            CLSCTX_ALL, nullptr, reinterpret_cast<void**>(&pVol))) && pVol)
        {
            float scalar = 0.0f;
            pVol->GetMasterVolumeLevelScalar(&scalar);
            dev.masterVolume = scalar;
 
            BOOL muted = FALSE;
            pVol->GetMute(&muted);
            dev.isMuted = (muted != FALSE);
 
            pVol->Release();
        }
 
        return dev;
    }
 
} // namespace _Detail
 
// ============================================================
//  SECTION A1 — Device Enumeration
// ============================================================
 
/// Enumerate audio endpoints, optionally filtered by render/capture/all.
/// Only ACTIVE (plugged-in, enabled) devices are returned by default;
/// set includeInactive = true to include disabled/unplugged devices.
inline std::vector<AudioDevice> EnumerateDevices(
    AudioDeviceType filter = AudioDeviceType::All,
    bool includeInactive   = false)
{
    _Detail::ComGuard com;
    std::vector<AudioDevice> result;
 
    IMMDeviceEnumerator* pEnum = _Detail::CreateEnumerator();
    if (!pEnum) return result;
    auto enumGuard = Internal::MakeScopeGuard([&]{ pEnum->Release(); });
 
    // Retrieve default device IDs up-front so we can tag each device.
    auto getDefaultId = [&](EDataFlow flow, ERole role) -> std::wstring {
        IMMDevice* pDef = nullptr;
        if (FAILED(pEnum->GetDefaultAudioEndpoint(flow, role, &pDef)) || !pDef)
            return {};
        LPWSTR id = nullptr;
        pDef->GetId(&id);
        std::wstring wid = id ? id : L"";
        CoTaskMemFree(id);
        pDef->Release();
        return wid;
    };
 
    const std::wstring defRenderId       = getDefaultId(eRender,  eMultimedia);
    const std::wstring defCaptureId      = getDefaultId(eCapture, eMultimedia);
    const std::wstring defCommRenderId   = getDefaultId(eRender,  eCommunications);
    const std::wstring defCommCaptureId  = getDefaultId(eCapture, eCommunications);
 
    DWORD stateMask = DEVICE_STATE_ACTIVE;
    if (includeInactive)
        stateMask |= DEVICE_STATE_DISABLED | DEVICE_STATE_NOTPRESENT | DEVICE_STATE_UNPLUGGED;
 
    auto enumerateFlow = [&](EDataFlow flow, AudioDeviceType type) {
        IMMDeviceCollection* pColl = nullptr;
        if (FAILED(pEnum->EnumAudioEndpoints(flow, stateMask, &pColl)) || !pColl)
            return;
        UINT count = 0;
        pColl->GetCount(&count);
        for (UINT i = 0; i < count; ++i) {
            IMMDevice* pDev = nullptr;
            if (SUCCEEDED(pColl->Item(i, &pDev)) && pDev) {
                result.push_back(_Detail::PopulateDevice(
                    pDev,
                    defRenderId, defCaptureId,
                    defCommRenderId, defCommCaptureId,
                    type));
                pDev->Release();
            }
        }
        pColl->Release();
    };
 
    if (filter == AudioDeviceType::Render || filter == AudioDeviceType::All)
        enumerateFlow(eRender, AudioDeviceType::Render);
    if (filter == AudioDeviceType::Capture || filter == AudioDeviceType::All)
        enumerateFlow(eCapture, AudioDeviceType::Capture);
 
    return result;
}
 
/// Convenience — enumerate only output (render) devices.
inline std::vector<AudioDevice> GetOutputDevices(bool includeInactive = false) {
    return EnumerateDevices(AudioDeviceType::Render, includeInactive);
}
 
/// Convenience — enumerate only input (capture) devices.
inline std::vector<AudioDevice> GetInputDevices(bool includeInactive = false) {
    return EnumerateDevices(AudioDeviceType::Capture, includeInactive);
}
 
// ============================================================
//  SECTION A2 — Default Device Access
// ============================================================
 
/// Get the system default audio endpoint (multimedia role) for the given flow.
/// Returns std::nullopt if no device is available.
inline std::optional<AudioDevice> GetDefaultDevice(
    AudioDeviceType type = AudioDeviceType::Render)
{
    _Detail::ComGuard com;
 
    IMMDeviceEnumerator* pEnum = _Detail::CreateEnumerator();
    if (!pEnum) return std::nullopt;
    auto enumGuard = Internal::MakeScopeGuard([&]{ pEnum->Release(); });
 
    EDataFlow flow = (type == AudioDeviceType::Capture) ? eCapture : eRender;
 
    IMMDevice* pDef = nullptr;
    if (FAILED(pEnum->GetDefaultAudioEndpoint(flow, eMultimedia, &pDef)) || !pDef)
        return std::nullopt;
    auto devGuard = Internal::MakeScopeGuard([&]{ pDef->Release(); });
 
    // We need the default IDs to correctly tag the device
    auto getId = [&](EDataFlow f, ERole r) -> std::wstring {
        IMMDevice* d = nullptr;
        if (FAILED(pEnum->GetDefaultAudioEndpoint(f, r, &d)) || !d) return {};
        LPWSTR id = nullptr; d->GetId(&id);
        std::wstring wid = id ? id : L"";
        CoTaskMemFree(id); d->Release();
        return wid;
    };
 
    AudioDevice dev = _Detail::PopulateDevice(
        pDef,
        getId(eRender,  eMultimedia),
        getId(eCapture, eMultimedia),
        getId(eRender,  eCommunications),
        getId(eCapture, eCommunications),
        type);
    return dev;
}
 
/// Get the default render (speaker/headphone) device.
inline std::optional<AudioDevice> GetDefaultOutput() {
    return GetDefaultDevice(AudioDeviceType::Render);
}
 
/// Get the default capture (microphone) device.
inline std::optional<AudioDevice> GetDefaultInput() {
    return GetDefaultDevice(AudioDeviceType::Capture);
}
 
/// Get an AudioDevice by its WASAPI endpoint ID string.
/// Returns std::nullopt if the ID is not found or the device is not active.
inline std::optional<AudioDevice> GetDeviceById(const std::string& endpointId) {
    _Detail::ComGuard com;
 
    IMMDeviceEnumerator* pEnum = _Detail::CreateEnumerator();
    if (!pEnum) return std::nullopt;
    auto enumGuard = Internal::MakeScopeGuard([&]{ pEnum->Release(); });
 
    std::wstring wid = Str::ToWide(endpointId);
    IMMDevice* pDev = nullptr;
    if (FAILED(pEnum->GetDevice(wid.c_str(), &pDev)) || !pDev)
        return std::nullopt;
    auto devGuard = Internal::MakeScopeGuard([&]{ pDev->Release(); });
 
    // Determine flow direction so we can tag AudioDeviceType correctly
    IMMEndpoint* pEp = nullptr;
    AudioDeviceType devType = AudioDeviceType::Render;
    if (SUCCEEDED(pDev->QueryInterface(__uuidof(IMMEndpoint), reinterpret_cast<void**>(&pEp))) && pEp) {
        EDataFlow flow = eRender;
        pEp->GetDataFlow(&flow);
        devType = (flow == eCapture) ? AudioDeviceType::Capture : AudioDeviceType::Render;
        pEp->Release();
    }
 
    auto getId = [&](EDataFlow f, ERole r) -> std::wstring {
        IMMDevice* d = nullptr;
        if (FAILED(pEnum->GetDefaultAudioEndpoint(f, r, &d)) || !d) return {};
        LPWSTR id = nullptr; d->GetId(&id);
        std::wstring w = id ? id : L"";
        CoTaskMemFree(id); d->Release();
        return w;
    };
 
    AudioDevice dev = _Detail::PopulateDevice(
        pDev,
        getId(eRender,  eMultimedia),
        getId(eCapture, eMultimedia),
        getId(eRender,  eCommunications),
        getId(eCapture, eCommunications),
        devType);
    return dev;
}
 
// ============================================================
//  SECTION A3 — Volume & Mute Control
// ============================================================
 
/// Set the master volume for a device by endpoint ID. scalar ∈ [0.0, 1.0].
/// Returns true on success.
inline bool SetVolume(const std::string& endpointId, float scalar) {
    _Detail::ComGuard com;
 
    IMMDeviceEnumerator* pEnum = _Detail::CreateEnumerator();
    if (!pEnum) return false;
    auto enumGuard = Internal::MakeScopeGuard([&]{ pEnum->Release(); });
 
    IMMDevice* pDev = nullptr;
    if (FAILED(pEnum->GetDevice(Str::ToWide(endpointId).c_str(), &pDev)) || !pDev)
        return false;
    auto devGuard = Internal::MakeScopeGuard([&]{ pDev->Release(); });
 
    IAudioEndpointVolume* pVol = nullptr;
    if (FAILED(pDev->Activate(__uuidof(IAudioEndpointVolume),
        CLSCTX_ALL, nullptr, reinterpret_cast<void**>(&pVol))) || !pVol)
        return false;
    auto volGuard = Internal::MakeScopeGuard([&]{ pVol->Release(); });
 
    scalar = std::max(0.0f, std::min(1.0f, scalar));
    return SUCCEEDED(pVol->SetMasterVolumeLevelScalar(scalar, nullptr));
}
 
/// Set mute state for a device by endpoint ID.
inline bool SetMute(const std::string& endpointId, bool mute) {
    _Detail::ComGuard com;
 
    IMMDeviceEnumerator* pEnum = _Detail::CreateEnumerator();
    if (!pEnum) return false;
    auto enumGuard = Internal::MakeScopeGuard([&]{ pEnum->Release(); });
 
    IMMDevice* pDev = nullptr;
    if (FAILED(pEnum->GetDevice(Str::ToWide(endpointId).c_str(), &pDev)) || !pDev)
        return false;
    auto devGuard = Internal::MakeScopeGuard([&]{ pDev->Release(); });
 
    IAudioEndpointVolume* pVol = nullptr;
    if (FAILED(pDev->Activate(__uuidof(IAudioEndpointVolume),
        CLSCTX_ALL, nullptr, reinterpret_cast<void**>(&pVol))) || !pVol)
        return false;
    auto volGuard = Internal::MakeScopeGuard([&]{ pVol->Release(); });
 
    return SUCCEEDED(pVol->SetMute(mute ? TRUE : FALSE, nullptr));
}
 
/// Toggle mute on the default render endpoint. Returns the new mute state.
inline bool ToggleMuteDefault() {
    auto dev = GetDefaultOutput();
    if (!dev) return false;
 
#ifdef WINUTILS_AUDIO_QT
    std::string id = dev->id.toStdString();
#else
    std::string id = dev->id;
#endif
 
    bool newMute = !dev->isMuted;
    SetMute(id, newMute);
    return newMute;
}
 
// ============================================================
//  SECTION A4 — Windows Audio Service Management
// ============================================================
 
/// Restart the Windows Audio service ("AudioSrv") and its dependency
/// "AudioEndpointBuilder". Both services are stopped in dependency order
/// and restarted in reverse. This clears stuck audio states without a reboot.
///
/// Requires: Administrator privileges.
/// Effects:  All audio output is briefly silent during restart (~1-3 seconds).
///
/// Returns: true if both services were successfully restarted.
inline bool RestartAudioService(DWORD timeoutMs = 10000) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    auto scmGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(hSCM); });
 
    // Stop and start two services in the correct dependency order.
    // AudioEndpointBuilder is a dependency of AudioSrv — stop AudioSrv first,
    // then AudioEndpointBuilder; restart AudioEndpointBuilder first, then AudioSrv.
    const wchar_t* kSvc1 = L"Audiosrv";             // Windows Audio
    const wchar_t* kSvc2 = L"AudioEndpointBuilder"; // Windows Audio Endpoint Builder
 
    auto stopService = [&](const wchar_t* name) -> bool {
        SC_HANDLE h = OpenServiceW(hSCM, name, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_START);
        if (!h) return false;
        auto hGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(h); });
 
        SERVICE_STATUS_PROCESS ssp{};
        DWORD bytesNeeded = 0;
        QueryServiceStatusEx(h, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
 
        if (ssp.dwCurrentState == SERVICE_STOPPED) return true;  // already stopped
 
        SERVICE_STATUS ss{};
        ControlService(h, SERVICE_CONTROL_STOP, &ss);
 
        // Wait for stop
        DWORD elapsed = 0;
        while (ssp.dwCurrentState != SERVICE_STOPPED && elapsed < timeoutMs) {
            ::Sleep(250);
            elapsed += 250;
            QueryServiceStatusEx(h, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
        }
        return ssp.dwCurrentState == SERVICE_STOPPED;
    };
 
    auto startService = [&](const wchar_t* name) -> bool {
        SC_HANDLE h = OpenServiceW(hSCM, name, SERVICE_START | SERVICE_QUERY_STATUS);
        if (!h) return false;
        auto hGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(h); });
 
        StartServiceW(h, 0, nullptr);
 
        SERVICE_STATUS_PROCESS ssp{};
        DWORD bytesNeeded = 0;
        DWORD elapsed = 0;
        do {
            ::Sleep(250);
            elapsed += 250;
            QueryServiceStatusEx(h, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
        } while (ssp.dwCurrentState == SERVICE_START_PENDING && elapsed < timeoutMs);
 
        return ssp.dwCurrentState == SERVICE_RUNNING;
    };
 
    // Stop order: AudioSrv → AudioEndpointBuilder
    stopService(kSvc1);
    stopService(kSvc2);
 
    // Start order: AudioEndpointBuilder → AudioSrv
    bool ok = startService(kSvc2);
    ok     &= startService(kSvc1);
    return ok;
}
 
/// Query the running state of the Windows Audio service.
/// Returns true if "AudioSrv" is currently SERVICE_RUNNING.
inline bool IsAudioServiceRunning() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    auto scmGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(hSCM); });
 
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"Audiosrv", SERVICE_QUERY_STATUS);
    if (!hSvc) return false;
    auto svcGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(hSvc); });
 
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
 
    return ssp.dwCurrentState == SERVICE_RUNNING;
}
 
/// Stop the Windows Audio service.
/// Requires: Administrator privileges.
inline bool StopAudioService(DWORD timeoutMs = 5000) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    auto scmGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(hSCM); });
 
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"Audiosrv",
        SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) return false;
    auto svcGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(hSvc); });
 
    SERVICE_STATUS ss{};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
 
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0, elapsed = 0;
    do {
        ::Sleep(200);
        elapsed += 200;
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
    } while (ssp.dwCurrentState != SERVICE_STOPPED && elapsed < timeoutMs);
 
    return ssp.dwCurrentState == SERVICE_STOPPED;
}
 
/// Start the Windows Audio service.
/// Requires: Administrator privileges.
inline bool StartAudioService(DWORD timeoutMs = 5000) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    auto scmGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(hSCM); });
 
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"Audiosrv",
        SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) return false;
    auto svcGuard = Internal::MakeScopeGuard([&]{ CloseServiceHandle(hSvc); });
 
    StartServiceW(hSvc, 0, nullptr);
 
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0, elapsed = 0;
    do {
        ::Sleep(200);
        elapsed += 200;
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
    } while (ssp.dwCurrentState == SERVICE_START_PENDING && elapsed < timeoutMs);
 
    return ssp.dwCurrentState == SERVICE_RUNNING;
}
 
// ============================================================
//  SECTION A5 — Convenience Queries
// ============================================================
 
/// Returns true if any active output device is currently muted.
inline bool IsAnyOutputMuted() {
    for (auto& dev : GetOutputDevices())
        if (dev.isMuted) return true;
    return false;
}
 
/// Get the number of active audio output devices.
inline int GetOutputDeviceCount() {
    return static_cast<int>(GetOutputDevices().size());
}
 
/// Get the number of active audio input devices.
inline int GetInputDeviceCount() {
    return static_cast<int>(GetInputDevices().size());
}
 
/// Get the friendly name of the default output device, or an empty string.
inline std::string GetDefaultOutputName() {
    auto dev = GetDefaultOutput();
    if (!dev) return {};
#ifdef WINUTILS_AUDIO_QT
    return dev->friendlyName.toStdString();
#else
    return dev->friendlyName;
#endif
}
 
/// Get the friendly name of the default input device, or an empty string.
inline std::string GetDefaultInputName() {
    auto dev = GetDefaultInput();
    if (!dev) return {};
#ifdef WINUTILS_AUDIO_QT
    return dev->friendlyName.toStdString();
#else
    return dev->friendlyName;
#endif
}
 
} // namespace Audio
} // namespace WinUtils
 
// ============================================================
//  Qt meta-type registration helper
//  Call this once (e.g. in main()) when WINUTILS_AUDIO_QT is defined.
//
//  Example:
//    WinUtils::Audio::RegisterQtTypes();
// ============================================================
#ifdef WINUTILS_AUDIO_QT
namespace WinUtils::Audio {
    inline void RegisterQtTypes() {
        qRegisterMetaType<WinUtils::Audio::AudioDevice>("WinUtils::Audio::AudioDevice");
        qRegisterMetaType<QList<WinUtils::Audio::AudioDevice>>("QList<WinUtils::Audio::AudioDevice>");
        qRegisterMetaType<WinUtils::Audio::AudioDeviceType>("WinUtils::Audio::AudioDeviceType");
    }
}
#endif
 
#endif // WINUTILS_AUDIO_HPP