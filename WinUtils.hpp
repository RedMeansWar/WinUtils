/*
 * ============================================================================
 * WinUtils.hpp
 * Part of the WinUtils project — A comprehensive Windows utility header library
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
 * This software interacts directly with the Windows operating system, including
 * the Win32 API, system registry, file system, and process model. Improper use
 * may cause system instability, data loss, or unintended behaviour.
 *
 * The author accepts no responsibility for damages arising from the use or
 * misuse of this software. You are solely responsible for ensuring that your
 * use complies with applicable laws and that you have appropriate authorization
 * for any system you operate on.
 *
 * ============================================================================
 *
 * Requires : Windows (Win32 API), C++17 or later
 * Companion: WinPower.hpp (low-level / admin features)
 * Reference: See README.md for full namespace and function documentation
 *
 * ============================================================================
*/


#pragma once
#ifndef WIN_UTILS_HPP
#define WIN_UTILS_HPP

// ---- Windows headers ----
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winreg.h>
#include <dwmapi.h>
#include <bcrypt.h>
#include <shobjidl.h>
#include <mmsystem.h>
#include <aclapi.h>
#include <sddl.h>
#include <io.h>
#include <comdef.h>
#include <wbemidl.h>
#include <winioctl.h>
#include <winsock.h>

// ---- Standard headers ----
#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <algorithm>
#include <map>
#include <cmath>

// ---- Pragma comments (auto-link) ----
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace WinUtils {

// ============================================================
//  SECTION 1 — String Utilities
// ============================================================
namespace Str {

    /// Convert UTF-8 std::string to UTF-16 std::wstring
    inline std::wstring ToWide(const std::string& str) {
        if (str.empty()) return {};
        int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        std::wstring result(size - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, result.data(), size);
        return result;
    }

    /// Convert UTF-16 std::wstring to UTF-8 std::string
    inline std::string ToNarrow(const std::wstring& wstr) {
        if (wstr.empty()) return {};
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, result.data(), size, nullptr, nullptr);
        return result;
    }

    /// Format a string like printf
    template<typename... Args>
    inline std::string Format(const std::string& fmt, Args&&... args) {
        int size = std::snprintf(nullptr, 0, fmt.c_str(), std::forward<Args>(args)...);
        std::string buf(size + 1, '\0');
        std::snprintf(buf.data(), buf.size(), fmt.c_str(), std::forward<Args>(args)...);
        buf.resize(size);
        return buf;
    }

    /// Split a string by delimiter
    inline std::vector<std::string> Split(const std::string& s, char delim) {
        std::vector<std::string> result;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, delim))
            result.push_back(item);
        return result;
    }

    /// Trim whitespace from both ends
    inline std::string Trim(std::string s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char c){ return !std::isspace(c); }));
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char c){ return !std::isspace(c); }).base(), s.end());
        return s;
    }

    /// Replace all occurrences of `from` with `to`
    inline std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
        size_t pos = 0;
        while ((pos = str.find(from, pos)) != std::string::npos) {
            str.replace(pos, from.size(), to);
            pos += to.size();
        }
        return str;
    }

} // namespace Str

// ============================================================
//  SECTION 2 — Dialog Boxes
// ============================================================
namespace Dialog {

    /// Show a simple message box
    inline void Message(const std::string& text, const std::string& title = "Message", UINT flags = MB_OK | MB_ICONINFORMATION) {
        MessageBoxW(nullptr, Str::ToWide(text).c_str(), Str::ToWide(title).c_str(), flags);
    }

    /// Show an error dialog
    inline void Error(const std::string& text, const std::string& title = "Error") {
        MessageBoxW(nullptr, Str::ToWide(text).c_str(), Str::ToWide(title).c_str(), MB_OK | MB_ICONERROR);
    }

    /// Show a warning dialog
    inline void Warning(const std::string& text, const std::string& title = "Warning") {
        MessageBoxW(nullptr, Str::ToWide(text).c_str(), Str::ToWide(title).c_str(), MB_OK | MB_ICONWARNING);
    }

    /// Show a Yes/No dialog. Returns true if Yes was clicked.
    inline bool YesNo(const std::string& text, const std::string& title = "Confirm") {
        return MessageBoxW(nullptr, Str::ToWide(text).c_str(), Str::ToWide(title).c_str(), MB_YESNO | MB_ICONQUESTION) == IDYES;
    }

    /// Show a Yes/No/Cancel dialog. Returns IDYES, IDNO, or IDCANCEL.
    inline int YesNoCancel(const std::string& text, const std::string& title = "Confirm") {
        return MessageBoxW(nullptr, Str::ToWide(text).c_str(), Str::ToWide(title).c_str(), MB_YESNOCANCEL | MB_ICONQUESTION);
    }

    /// Open file dialog. Returns chosen path or empty string if cancelled.
    inline std::string OpenFile(const std::string& filter = "All Files\0*.*\0", const std::string& title = "Open File") {
        wchar_t buf[MAX_PATH] = {};
        OPENFILENAMEW ofn{};
        std::wstring wfilter = Str::ToWide(filter);
        // Replace \0 separators (they get squashed in std::string, pass raw)
        ofn.lStructSize = sizeof(ofn);
        ofn.lpstrFilter = wfilter.c_str();
        ofn.lpstrFile   = buf;
        ofn.nMaxFile    = MAX_PATH;
        ofn.lpstrTitle  = Str::ToWide(title).c_str();
        ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        if (GetOpenFileNameW(&ofn)) return Str::ToNarrow(buf);
        return {};
    }

    /// Save file dialog. Returns chosen path or empty string if cancelled.
    inline std::string SaveFile(const std::string& filter = "All Files\0*.*\0", const std::string& defaultExt = "", const std::string& title = "Save File") {
        wchar_t buf[MAX_PATH] = {};
        OPENFILENAMEW ofn{};
        std::wstring wfilter  = Str::ToWide(filter);
        std::wstring wdefExt  = Str::ToWide(defaultExt);
        std::wstring wtitle   = Str::ToWide(title);
        ofn.lStructSize    = sizeof(ofn);
        ofn.lpstrFilter    = wfilter.c_str();
        ofn.lpstrFile      = buf;
        ofn.nMaxFile       = MAX_PATH;
        ofn.lpstrDefExt    = wdefExt.c_str();
        ofn.lpstrTitle     = wtitle.c_str();
        ofn.Flags          = OFN_OVERWRITEPROMPT;
        if (GetSaveFileNameW(&ofn)) return Str::ToNarrow(buf);
        return {};
    }

    /// Browse for a folder. Returns selected path or empty string if cancelled.
    inline std::string BrowseFolder(const std::string& title = "Select Folder") {
        BROWSEINFOW bi{};
        std::wstring wtitle = Str::ToWide(title);
        bi.lpszTitle = wtitle.c_str();
        bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
        if (!pidl) return {};
        wchar_t path[MAX_PATH] = {};
        SHGetPathFromIDListW(pidl, path);
        CoTaskMemFree(pidl);
        return Str::ToNarrow(path);
    }

    /// Show an input dialog using a quick InputBox (via VBScript / fallback: returns empty)
    /// NOTE: This spins up a tiny VBScript process as Win32 has no native InputBox.
    inline std::string InputBox(const std::string& prompt, const std::string& title = "Input", const std::string& defaultValue = "") {
        // Write temp vbs
        char tmpPath[MAX_PATH], tmpFile[MAX_PATH];
        GetTempPathA(MAX_PATH, tmpPath);
        GetTempFileNameA(tmpPath, "wu_", 0, tmpFile);
        std::string vbsPath = std::string(tmpFile) + ".vbs";
        std::string outPath = std::string(tmpFile) + ".txt";
        std::ofstream vbs(vbsPath);
        vbs << "Dim r\n"
            << "r = InputBox(\"" << Str::ReplaceAll(prompt, "\"", "\"\"") << "\", \""
            << Str::ReplaceAll(title, "\"", "\"\"") << "\", \""
            << Str::ReplaceAll(defaultValue, "\"", "\"\"") << "\")\n"
            << "Open \"" << Str::ReplaceAll(outPath, "\\", "\\") << "\" For Output As #1\n"
            << "Print #1, r\n"
            << "Close #1\n";
        vbs.close();
        ShellExecuteA(nullptr, "open", "wscript.exe", vbsPath.c_str(), nullptr, SW_HIDE);
        // Wait for output
        for (int i = 0; i < 100; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::ifstream f(outPath);
            if (f.good()) {
                std::string line;
                std::getline(f, line);
                DeleteFileA(vbsPath.c_str());
                DeleteFileA(outPath.c_str());
                DeleteFileA(tmpFile);
                return Str::Trim(line);
            }
        }
        DeleteFileA(vbsPath.c_str());
        DeleteFileA(tmpFile);
        return {};
    }

} // namespace Dialog

// ============================================================
//  SECTION 3 — File & Directory Utilities
// ============================================================
namespace File {

    namespace fs = std::filesystem;

    /// Create a file with optional content
    inline bool Create(const std::string& path, const std::string& content = "") {
        std::ofstream f(path);
        if (!f.is_open()) return false;
        f << content;
        return true;
    }

    /// Read entire file into a string
    inline std::optional<std::string> ReadAll(const std::string& path) {
        std::ifstream f(path, std::ios::in | std::ios::binary);
        if (!f.is_open()) return std::nullopt;
        return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }

    /// Write string to file (overwrite)
    inline bool WriteAll(const std::string& path, const std::string& content) {
        std::ofstream f(path, std::ios::out | std::ios::binary);
        if (!f.is_open()) return false;
        f << content;
        return f.good();
    }

    /// Append string to file
    inline bool Append(const std::string& path, const std::string& content) {
        std::ofstream f(path, std::ios::app | std::ios::binary);
        if (!f.is_open()) return false;
        f << content;
        return f.good();
    }

    /// Delete a file
    inline bool Delete(const std::string& path) {
        return DeleteFileW(Str::ToWide(path).c_str()) != 0;
    }

    /// Copy a file to destination
    inline bool Copy(const std::string& src, const std::string& dst, bool overwrite = true) {
        return CopyFileW(Str::ToWide(src).c_str(), Str::ToWide(dst).c_str(), !overwrite) != 0;
    }

    /// Move / rename a file
    inline bool Move(const std::string& src, const std::string& dst) {
        return MoveFileW(Str::ToWide(src).c_str(), Str::ToWide(dst).c_str()) != 0;
    }

    /// Check if file exists
    inline bool Exists(const std::string& path) {
        return fs::exists(path);
    }

    /// Get file size in bytes
    inline std::optional<uintmax_t> Size(const std::string& path) {
        std::error_code ec;
        auto s = fs::file_size(path, ec);
        if (ec) return std::nullopt;
        return s;
    }

    /// Create a directory (and all parents)
    inline bool CreateDir(const std::string& path) {
        std::error_code ec;
        return fs::create_directories(path, ec);
    }

    /// Delete a directory (recursively)
    inline bool DeleteDir(const std::string& path) {
        std::error_code ec;
        fs::remove_all(path, ec);
        return !ec;
    }

    /// List files in a directory (non-recursive)
    inline std::vector<std::string> ListDir(const std::string& path, const std::string& ext = "") {
        std::vector<std::string> result;
        std::error_code ec;
        for (auto& entry : fs::directory_iterator(path, ec)) {
            if (ec) break;
            if (ext.empty() || entry.path().extension() == ext)
                result.push_back(entry.path().string());
        }
        return result;
    }

    /// Get the current executable's directory
    inline std::string ExeDir() {
        wchar_t buf[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, buf, MAX_PATH);
        return fs::path(buf).parent_path().string();
    }

    /// Get the Windows temp directory
    inline std::string TempDir() {
        wchar_t buf[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, buf);
        return Str::ToNarrow(buf);
    }

    /// Get a unique temp file path
    inline std::string TempFile(const std::string& prefix = "tmp") {
        wchar_t tmpPath[MAX_PATH] = {}, tmpFile[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tmpPath);
        GetTempFileNameW(tmpPath, Str::ToWide(prefix).c_str(), 0, tmpFile);
        return Str::ToNarrow(tmpFile);
    }

} // namespace File

// ============================================================
//  SECTION 4 — Mouse Cursor Utilities
// ============================================================
namespace Mouse {

    /// Get current cursor position
    inline POINT GetPos() {
        POINT p{};
        GetCursorPos(&p);
        return p;
    }

    /// Set cursor position (screen coordinates)
    inline void SetPos(int x, int y) {
        SetCursorPos(x, y);
    }

    /// Move cursor relative to current position
    inline void MoveBy(int dx, int dy) {
        POINT p = GetPos();
        SetCursorPos(p.x + dx, p.y + dy);
    }

    /// Hide the mouse cursor (decrements internal counter; call once)
    inline void Hide() {
        while (ShowCursor(FALSE) >= 0);
    }

    /// Show the mouse cursor (increments internal counter)
    inline void Show() {
        while (ShowCursor(TRUE) < 0);
    }

    /// Simulates a left click at the current cursor position
    inline void LeftClick() {
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
        mouse_event(MOUSEEVENTF_LEFTUP,   0, 0, 0, 0);
    }

    /// Simulates a right click at the current cursor position
    inline void RightClick() {
        mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
        mouse_event(MOUSEEVENTF_RIGHTUP,   0, 0, 0, 0);
    }

    /// Simulates a double left click
    inline void DoubleClick() {
        LeftClick();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        LeftClick();
    }

    /// Scroll the mouse wheel. Positive = up, negative = down.
    inline void Scroll(int delta) {
        mouse_event(MOUSEEVENTF_WHEEL, 0, 0, static_cast<DWORD>(delta * WHEEL_DELTA), 0);
    }

    /// Move cursor to position and left-click
    inline void ClickAt(int x, int y) {
        SetPos(x, y);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        LeftClick();
    }

    /// Change the cursor to a standard system cursor
    /// cursorId: IDC_ARROW, IDC_WAIT, IDC_CROSS, IDC_HAND, IDC_IBEAM, IDC_NO, IDC_SIZEALL, etc.
    inline void SetCursorIcon(LPCWSTR cursorId = IDC_ARROW) {
        HCURSOR hc = LoadCursorW(nullptr, cursorId);
        SetCursor(hc);
    }

    /// Confine cursor to a rectangle region (pass NULL to release)
    inline void Confine(RECT* rect) {
        ClipCursor(rect);
    }

    /// Release any cursor confinement
    inline void ReleaseConfinement() {
        ClipCursor(nullptr);
    }

    /// Smooth animated move from current position to (x, y) over `ms` milliseconds
    inline void SmoothMove(int x, int y, int ms = 300, int steps = 60) {
        POINT start = GetPos();
        for (int i = 1; i <= steps; ++i) {
            int nx = start.x + (x - start.x) * i / steps;
            int ny = start.y + (y - start.y) * i / steps;
            SetCursorPos(nx, ny);
            std::this_thread::sleep_for(std::chrono::milliseconds(ms / steps));
        }
    }

} // namespace Mouse

// ============================================================
//  SECTION 5 — Keyboard Utilities
// ============================================================
namespace Keyboard {

    /// Simulate pressing and releasing a key (virtual key code)
    inline void Press(WORD vk) {
        INPUT in{};
        in.type       = INPUT_KEYBOARD;
        in.ki.wVk     = vk;
        SendInput(1, &in, sizeof(INPUT));
        in.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &in, sizeof(INPUT));
    }

    /// Simulate a key down event
    inline void KeyDown(WORD vk) {
        INPUT in{};
        in.type   = INPUT_KEYBOARD;
        in.ki.wVk = vk;
        SendInput(1, &in, sizeof(INPUT));
    }

    /// Simulate a key up event
    inline void KeyUp(WORD vk) {
        INPUT in{};
        in.type       = INPUT_KEYBOARD;
        in.ki.wVk     = vk;
        in.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &in, sizeof(INPUT));
    }

    /// Type a unicode string
    inline void TypeText(const std::wstring& text) {
        for (wchar_t ch : text) {
            INPUT in[2]{};
            in[0].type           = INPUT_KEYBOARD;
            in[0].ki.wScan       = ch;
            in[0].ki.dwFlags     = KEYEVENTF_UNICODE;
            in[1].type           = INPUT_KEYBOARD;
            in[1].ki.wScan       = ch;
            in[1].ki.dwFlags     = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            SendInput(2, in, sizeof(INPUT));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    inline void TypeText(const std::string& text) {
        TypeText(Str::ToWide(text));
    }

    /// Check if a key is currently held down
    inline bool IsDown(WORD vk) {
        return (GetAsyncKeyState(vk) & 0x8000) != 0;
    }

    /// Simulate Ctrl+C (copy)
    inline void Copy() { KeyDown(VK_CONTROL); Press('C'); KeyUp(VK_CONTROL); }

    /// Simulate Ctrl+V (paste)
    inline void Paste() { KeyDown(VK_CONTROL); Press('V'); KeyUp(VK_CONTROL); }

    /// Simulate Ctrl+Z (undo)
    inline void Undo() { KeyDown(VK_CONTROL); Press('Z'); KeyUp(VK_CONTROL); }

} // namespace Keyboard

// ============================================================
//  SECTION 6 — Clipboard Utilities
// ============================================================
namespace Clipboard {

    /// Get text from clipboard
    inline std::optional<std::string> GetText() {
        if (!OpenClipboard(nullptr)) return std::nullopt;
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        if (!h) { CloseClipboard(); return std::nullopt; }
        auto* ptr = static_cast<wchar_t*>(GlobalLock(h));
        std::wstring ws(ptr ? ptr : L"");
        GlobalUnlock(h);
        CloseClipboard();
        return Str::ToNarrow(ws);
    }

    /// Set clipboard text
    inline bool SetText(const std::string& text) {
        std::wstring ws = Str::ToWide(text);
        size_t bytes = (ws.size() + 1) * sizeof(wchar_t);
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (!h) return false;
        memcpy(GlobalLock(h), ws.c_str(), bytes);
        GlobalUnlock(h);
        if (!OpenClipboard(nullptr)) { GlobalFree(h); return false; }
        EmptyClipboard();
        SetClipboardData(CF_UNICODETEXT, h);
        CloseClipboard();
        return true;
    }

    /// Clear clipboard
    inline bool Clear() {
        if (!OpenClipboard(nullptr)) return false;
        EmptyClipboard();
        CloseClipboard();
        return true;
    }

} // namespace Clipboard

// ============================================================
//  SECTION 7 — Process & Shell Utilities
// ============================================================
namespace Process {

    /// Open a URL in the default browser
    inline bool OpenURL(const std::string& url) {
        return reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", Str::ToWide(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL)) > 32;
    }

    /// Open a file with its default application
    inline bool OpenFile(const std::string& path) {
        return reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", Str::ToWide(path).c_str(), nullptr, nullptr, SW_SHOWNORMAL)) > 32;
    }

    /// Run an executable with optional arguments
    inline bool Run(const std::string& exe, const std::string& args = "", bool asAdmin = false, bool wait = false) {
        SHELLEXECUTEINFOW sei{};
        sei.cbSize      = sizeof(sei);
        sei.lpVerb      = asAdmin ? L"runas" : L"open";
        sei.lpFile      = Str::ToWide(exe).c_str();
        sei.lpParameters = Str::ToWide(args).c_str();
        sei.nShow       = SW_SHOWNORMAL;
        sei.fMask       = SEE_MASK_NOCLOSEPROCESS;
        if (!ShellExecuteExW(&sei)) return false;
        if (wait && sei.hProcess) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
        }
        return true;
    }

    /// Run a command and capture its stdout output
    inline std::optional<std::string> RunCapture(const std::string& cmd) {
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
        if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return std::nullopt;
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb          = sizeof(si);
        si.dwFlags     = STARTF_USESTDHANDLES;
        si.hStdOutput  = hWrite;
        si.hStdError   = hWrite;
        std::wstring wcmd = Str::ToWide(cmd);
        if (!CreateProcessW(nullptr, wcmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hRead); CloseHandle(hWrite);
            return std::nullopt;
        }
        CloseHandle(hWrite);
        std::string output;
        char buf[4096];
        DWORD bytesRead;
        while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead)
            output.append(buf, bytesRead);
        CloseHandle(hRead);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return output;
    }

    /// Kill a process by its PID
    inline bool Kill(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!h) return false;
        bool ok = TerminateProcess(h, 1) != 0;
        CloseHandle(h);
        return ok;
    }

    /// Get the current process's PID
    inline DWORD CurrentPID() {
        return GetCurrentProcessId();
    }

    /// List running processes: returns map of PID -> process name
    inline std::map<DWORD, std::string> ListProcesses() {
        std::map<DWORD, std::string> result;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return result;
        PROCESSENTRY32W pe{ sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(snap, &pe)) {
            do {
                result[pe.th32ProcessID] = Str::ToNarrow(pe.szExeFile);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return result;
    }

    /// Check if a process with a given name is running
    inline bool IsRunning(const std::string& name) {
        auto procs = ListProcesses();
        std::string lname = name;
        std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
        for (auto& [pid, n] : procs) {
            std::string ln = n;
            std::transform(ln.begin(), ln.end(), ln.begin(), ::tolower);
            if (ln == lname) return true;
        }
        return false;
    }

    /// Exit the current application
    inline void Exit(int code = 0) {
        ExitProcess(static_cast<UINT>(code));
    }

} // namespace Process

// ============================================================
//  SECTION 8 — Window Utilities
// ============================================================
namespace Window {

    /// Find a window by its title (exact match)
    inline HWND FindByTitle(const std::string& title) {
        return FindWindowW(nullptr, Str::ToWide(title).c_str());
    }

    /// Set a window's title
    inline bool SetTitle(HWND hwnd, const std::string& title) {
        return SetWindowTextW(hwnd, Str::ToWide(title).c_str()) != 0;
    }

    /// Get a window's title
    inline std::string GetTitle(HWND hwnd) {
        wchar_t buf[512] = {};
        GetWindowTextW(hwnd, buf, 512);
        return Str::ToNarrow(buf);
    }

    /// Show/hide a window
    inline void Show(HWND hwnd, bool visible = true) {
        ShowWindow(hwnd, visible ? SW_SHOW : SW_HIDE);
    }

    /// Minimize / maximize / restore a window
    inline void Minimize(HWND hwnd)  { ShowWindow(hwnd, SW_MINIMIZE);  }
    inline void Maximize(HWND hwnd)  { ShowWindow(hwnd, SW_MAXIMIZE);  }
    inline void Restore(HWND hwnd)   { ShowWindow(hwnd, SW_RESTORE);   }

    /// Bring a window to the foreground
    inline void BringToFront(HWND hwnd) {
        SetForegroundWindow(hwnd);
    }

    /// Move and resize a window
    inline void SetBounds(HWND hwnd, int x, int y, int w, int h) {
        MoveWindow(hwnd, x, y, w, h, TRUE);
    }

    /// Get the HWND of the current console window (if any)
    inline HWND GetConsole() {
        return GetConsoleWindow();
    }

    /// Toggle always-on-top for a window
    inline void SetAlwaysOnTop(HWND hwnd, bool onTop) {
        SetWindowPos(hwnd, onTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    }

    /// Set window transparency (0 = invisible, 255 = opaque)
    inline void SetOpacity(HWND hwnd, BYTE alpha) {
        SetWindowLongW(hwnd, GWL_EXSTYLE, GetWindowLongW(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
        SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA);
    }

    /// Get screen resolution
    inline SIZE GetScreenSize() {
        return { GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) };
    }

    /// Center a window on the screen
    inline void CenterOnScreen(HWND hwnd) {
        RECT r{};
        GetWindowRect(hwnd, &r);
        int w = r.right  - r.left;
        int h = r.bottom - r.top;
        int sx = GetSystemMetrics(SM_CXSCREEN);
        int sy = GetSystemMetrics(SM_CYSCREEN);
        SetWindowPos(hwnd, nullptr, (sx - w) / 2, (sy - h) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

    // ----------------------------------------------------------
    //  Enumeration
    // ----------------------------------------------------------

    struct WindowInfo {
        HWND        hwnd;
        std::string title;
        DWORD       pid;
        bool        visible;
    };

    inline BOOL CALLBACK _EnumWindowsProc(HWND hwnd, LPARAM lp) {
        auto* list = reinterpret_cast<std::vector<WindowInfo>*>(lp);
        wchar_t buf[512] = {};
        GetWindowTextW(hwnd, buf, 512);
        DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
        list->push_back({ hwnd, Str::ToNarrow(buf), pid, IsWindowVisible(hwnd) != FALSE });
        return TRUE;
    }

    /// Enumerate all top-level windows
    inline std::vector<WindowInfo> EnumAll() {
        std::vector<WindowInfo> list;
        EnumWindows(_EnumWindowsProc, reinterpret_cast<LPARAM>(&list));
        return list;
    }

    /// Get all windows belonging to a specific PID
    inline std::vector<WindowInfo> EnumByProcess(DWORD pid) {
        auto all = EnumAll();
        std::vector<WindowInfo> result;
        for (auto& w : all)
            if (w.pid == pid) result.push_back(w);
        return result;
    }

    /// Get the HWND of the window directly under screen point (x, y)
    inline HWND GetAtPoint(int x, int y) {
        POINT p{ x, y };
        return WindowFromPoint(p);
    }

    // ----------------------------------------------------------
    //  Layout & Snapping
    // ----------------------------------------------------------

    /// Snap a window to the left half of the screen
    inline void SnapLeft(HWND hwnd) {
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        Restore(hwnd);
        SetBounds(hwnd, 0, 0, sw / 2, sh);
    }

    /// Snap a window to the right half of the screen
    inline void SnapRight(HWND hwnd) {
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        Restore(hwnd);
        SetBounds(hwnd, sw / 2, 0, sw / 2, sh);
    }

    /// Snap a window to the top half of the screen
    inline void SnapTop(HWND hwnd) {
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        Restore(hwnd);
        SetBounds(hwnd, 0, 0, sw, sh / 2);
    }

    /// Snap a window to the bottom half of the screen
    inline void SnapBottom(HWND hwnd) {
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        Restore(hwnd);
        SetBounds(hwnd, 0, sh / 2, sw, sh / 2);
    }

    /// Snap a window to one of the four screen corners
    /// corner: 0=top-left, 1=top-right, 2=bottom-left, 3=bottom-right
    inline void SnapCorner(HWND hwnd, int corner) {
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        int hw = sw / 2, hh = sh / 2;
        Restore(hwnd);
        switch (corner) {
            case 0: SetBounds(hwnd, 0,  0,  hw, hh); break;
            case 1: SetBounds(hwnd, hw, 0,  hw, hh); break;
            case 2: SetBounds(hwnd, 0,  hh, hw, hh); break;
            case 3: SetBounds(hwnd, hw, hh, hw, hh); break;
        }
    }

    /// Snap a window to fullscreen (not maximized — actually resizes to screen bounds)
    inline void SnapFullscreen(HWND hwnd) {
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        Restore(hwnd);
        SetBounds(hwnd, 0, 0, sw, sh);
    }

    /// Tile a list of windows evenly across the screen
    inline void Tile(const std::vector<HWND>& windows) {
        if (windows.empty()) return;
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        int count = static_cast<int>(windows.size());
        int cols  = static_cast<int>(std::ceil(std::sqrt(static_cast<double>(count))));
        int rows  = (count + cols - 1) / cols;
        int w = sw / cols, h = sh / rows;
        for (int i = 0; i < count; ++i) {
            int col = i % cols, row = i / cols;
            Restore(windows[i]);
            SetBounds(windows[i], col * w, row * h, w, h);
        }
    }

    /// Cascade a list of windows diagonally across the screen
    inline void Cascade(const std::vector<HWND>& windows, int stepX = 30, int stepY = 30) {
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        int w  = static_cast<int>(sw * 0.6), h = static_cast<int>(sh * 0.6);
        for (int i = 0; i < static_cast<int>(windows.size()); ++i) {
            Restore(windows[i]);
            SetBounds(windows[i], i * stepX, i * stepY, w, h);
            BringToFront(windows[i]);
        }
    }

    // ----------------------------------------------------------
    //  Style Manipulation
    // ----------------------------------------------------------

    /// Remove title bar and borders (borderless window)
    inline void SetBorderless(HWND hwnd, bool borderless = true) {
        LONG style = GetWindowLongW(hwnd, GWL_STYLE);
        if (borderless)
            style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU);
        else
            style |=  (WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU);
        SetWindowLongW(hwnd, GWL_STYLE, style);
        SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }

    /// Make a window click-through (mouse events pass through it)
    inline void SetClickThrough(HWND hwnd, bool enable = true) {
        LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
        if (enable) ex |=  WS_EX_TRANSPARENT | WS_EX_LAYERED;
        else        ex &= ~WS_EX_TRANSPARENT;
        SetWindowLongW(hwnd, GWL_EXSTYLE, ex);
    }

    /// Hide a window from the taskbar and Alt+Tab switcher
    inline void SetToolWindow(HWND hwnd, bool enable = true) {
        LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
        if (enable) {
            ex |=  WS_EX_TOOLWINDOW;
            ex &= ~WS_EX_APPWINDOW;
        } else {
            ex &= ~WS_EX_TOOLWINDOW;
            ex |=  WS_EX_APPWINDOW;
        }
        SetWindowLongW(hwnd, GWL_EXSTYLE, ex);
        SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }

    /// Force dark mode title bar (Windows 10 build 18985+)
    inline void SetDarkTitleBar(HWND hwnd, bool dark = true) {
        BOOL val = dark ? TRUE : FALSE;
        // Try newer attribute first (Windows 11), fall back to older one
        if (FAILED(DwmSetWindowAttribute(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &val, sizeof(val))))
            DwmSetWindowAttribute(hwnd, 19, &val, sizeof(val));
    }

    /// Set rounded corners for a window (Windows 11+)
    /// preference: 0=default, 1=no rounding, 2=rounded, 3=small rounded
    inline void SetRoundedCorners(HWND hwnd, int preference = 2) {
        DwmSetWindowAttribute(hwnd, 33 /*DWMWA_WINDOW_CORNER_PREFERENCE*/, &preference, sizeof(preference));
    }

    /// Set the DWM caption/border accent color (Windows 11+)
    /// Pass a COLORREF e.g. RGB(255, 0, 128). Use 0xFFFFFFFE to reset to default.
    inline void SetAccentColor(HWND hwnd, COLORREF color) {
        DwmSetWindowAttribute(hwnd, 35 /*DWMWA_CAPTION_COLOR*/, &color, sizeof(color));
        DwmSetWindowAttribute(hwnd, 34 /*DWMWA_BORDER_COLOR*/,  &color, sizeof(color));
    }

    /// Reset DWM accent color to system default
    inline void ResetAccentColor(HWND hwnd) {
        SetAccentColor(hwnd, 0xFFFFFFFE);
    }

    // ----------------------------------------------------------
    //  State & Info
    // ----------------------------------------------------------

    /// Check if a window is minimized
    inline bool IsMinimized(HWND hwnd) { return IsIconic(hwnd) != FALSE; }

    /// Check if a window is maximized
    inline bool IsMaximized(HWND hwnd) { return IsZoomed(hwnd) != FALSE; }

    /// Check if a window is currently visible
    inline bool IsVisible(HWND hwnd)   { return IsWindowVisible(hwnd) != FALSE; }

    /// Check if a window handle is still valid/alive
    inline bool IsAlive(HWND hwnd)     { return IsWindow(hwnd) != FALSE; }

    /// Get the PID that owns a given window
    inline DWORD GetPID(HWND hwnd) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        return pid;
    }

    /// Get the window's outer bounding rectangle
    inline RECT GetBounds(HWND hwnd) {
        RECT r{};
        GetWindowRect(hwnd, &r);
        return r;
    }

    /// Get the window's inner client area size
    inline SIZE GetClientSize(HWND hwnd) {
        RECT r{};
        GetClientRect(hwnd, &r);
        return { r.right, r.bottom };
    }

    /// Flash the taskbar button to grab the user's attention
    /// count: number of flashes (0 = flash until foreground)
    inline void FlashTaskbar(HWND hwnd, UINT count = 5, DWORD intervalMs = 500) {
        FLASHWINFO fi{};
        fi.cbSize    = sizeof(fi);
        fi.hwnd      = hwnd;
        fi.dwFlags   = FLASHW_TRAY | (count == 0 ? FLASHW_TIMERNOFG : 0);
        fi.uCount    = count;
        fi.dwTimeout = intervalMs;
        FlashWindowEx(&fi);
    }

    /// Stop flashing a window's taskbar button
    inline void StopFlash(HWND hwnd) {
        FLASHWINFO fi{};
        fi.cbSize  = sizeof(fi);
        fi.hwnd    = hwnd;
        fi.dwFlags = FLASHW_STOP;
        FlashWindowEx(&fi);
    }

    // ----------------------------------------------------------
    //  Subclassing / Hooks
    // ----------------------------------------------------------

    /// Replace a window's WndProc (subclassing). Returns the old WndProc.
    /// Call the returned proc inside your new one via CallWindowProcW(oldProc, ...).
    inline WNDPROC SetWndProc(HWND hwnd, WNDPROC newProc) {
        return reinterpret_cast<WNDPROC>(
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(newProc)));
    }

    /// Restore a subclassed window's original WndProc
    inline void RestoreWndProc(HWND hwnd, WNDPROC originalProc) {
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(originalProc));
    }

    /// Shell hook — listen for global window create/destroy/activate events.
    /// Events: HSHELL_WINDOWCREATED, HSHELL_WINDOWDESTROYED, HSHELL_WINDOWACTIVATED, etc.
    /// Pass a message-only HWND and a WndProc that handles WM_SHELLHOOKMESSAGE.
    /// Returns the shell hook message ID to check in your WndProc.
    inline UINT RegisterShellHook(HWND hwnd) {
        RegisterShellHookWindow(hwnd);
        return RegisterWindowMessageW(L"SHELLHOOK");
    }

    /// Deregister the shell hook
    inline void DeregisterShellHook(HWND hwnd) {
        DeregisterShellHookWindow(hwnd);
    }

    /// Find a window using a partial title match (case-insensitive)
    inline HWND FindByPartialTitle(const std::string& partial) {
        std::string lower = partial;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto all = EnumAll();
        for (auto& w : all) {
            std::string t = w.title;
            std::transform(t.begin(), t.end(), t.begin(), ::tolower);
            if (t.find(lower) != std::string::npos) return w.hwnd;
        }
        return nullptr;
    }

    /// Find all visible windows whose title contains a substring (case-insensitive)
    inline std::vector<HWND> FindAllByPartialTitle(const std::string& partial) {
        std::string lower = partial;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        std::vector<HWND> result;
        for (auto& w : EnumAll()) {
            std::string t = w.title;
            std::transform(t.begin(), t.end(), t.begin(), ::tolower);
            if (t.find(lower) != std::string::npos) result.push_back(w.hwnd);
        }
        return result;
    }

    /// Send a message to a window and wait for it to be processed
    inline LRESULT Send(HWND hwnd, UINT msg, WPARAM wp = 0, LPARAM lp = 0) {
        return SendMessageW(hwnd, msg, wp, lp);
    }

    /// Post a message to a window's queue (non-blocking)
    inline bool Post(HWND hwnd, UINT msg, WPARAM wp = 0, LPARAM lp = 0) {
        return PostMessageW(hwnd, msg, wp, lp) != FALSE;
    }

    /// Close a window gracefully (sends WM_CLOSE)
    inline void Close(HWND hwnd) {
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    }

    /// Force-destroy a window immediately
    inline void ForceDestroy(HWND hwnd) {
        DestroyWindow(hwnd);
    }

} // namespace Window

// ============================================================
//  SECTION 9 — System Utilities
// ============================================================
namespace System {

    /// Get the current user's name
    inline std::string GetUsername() {
        wchar_t buf[256] = {};
        DWORD sz = 256;
        GetUserNameW(buf, &sz);
        return Str::ToNarrow(buf);
    }

    /// Get the computer name
    inline std::string GetComputerName() {
        wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
        ::GetComputerNameW(buf, &sz);
        return Str::ToNarrow(buf);
    }

    /// Get Windows version string
    inline std::string GetWindowsVersion() {
        OSVERSIONINFOEXW osvi{};
        osvi.dwOSVersionInfoSize = sizeof(osvi);
#pragma warning(suppress: 4996)
        GetVersionExW(reinterpret_cast<OSVERSIONINFOW*>(&osvi));
        return Str::Format("Windows %lu.%lu Build %lu", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }

    /// Get total and available physical memory in MB
    inline std::pair<uint64_t, uint64_t> GetMemoryMB() {
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        return { ms.ullTotalPhys / (1024 * 1024), ms.ullAvailPhys / (1024 * 1024) };
    }

    /// Get number of CPU logical processors
    inline DWORD GetCPUCount() {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return si.dwNumberOfProcessors;
    }

    /// Get special folder paths (CSIDL_DESKTOP, CSIDL_APPDATA, CSIDL_MYDOCUMENTS, etc.)
    inline std::string GetSpecialFolder(int csidl) {
        wchar_t buf[MAX_PATH] = {};
        SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, buf);
        return Str::ToNarrow(buf);
    }

    inline std::string Desktop()   { return GetSpecialFolder(CSIDL_DESKTOP);       }
    inline std::string AppData()   { return GetSpecialFolder(CSIDL_APPDATA);       }
    inline std::string Documents() { return GetSpecialFolder(CSIDL_MYDOCUMENTS);   }
    inline std::string Downloads() { return GetSpecialFolder(CSIDL_PROFILE) + "\\Downloads"; }
    inline std::string System32()  { return GetSpecialFolder(CSIDL_SYSTEM);        }

    /// Sleep for given milliseconds
    inline void Sleep(DWORD ms) {
        ::Sleep(ms);
    }

    /// Get current time as a formatted string  e.g. "2025-03-14 17:30:00"
    inline std::string Now(const std::string& fmt = "%Y-%m-%d %H:%M:%S") {
        auto t = std::time(nullptr);
        char buf[64] = {};
        std::strftime(buf, sizeof(buf), fmt.c_str(), std::localtime(&t));
        return buf;
    }

    /// Set an environment variable for the current process
    inline bool SetEnv(const std::string& name, const std::string& value) {
        return SetEnvironmentVariableW(Str::ToWide(name).c_str(), Str::ToWide(value).c_str()) != 0;
    }

    /// Get an environment variable
    inline std::optional<std::string> GetEnv(const std::string& name) {
        wchar_t buf[32767] = {};
        DWORD r = GetEnvironmentVariableW(Str::ToWide(name).c_str(), buf, 32767);
        if (!r) return std::nullopt;
        return Str::ToNarrow(buf);
    }

    /// Lock the workstation screen
    inline bool LockScreen() {
        return LockWorkStation() != 0;
    }

    /// Shutdown / Restart / Logoff
    enum class PowerAction { Shutdown, Restart, Logoff };
    inline bool Power(PowerAction action, bool force = false) {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp{};
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
            CloseHandle(hToken);
        }
        UINT flags = force ? EWX_FORCE : 0;
        switch (action) {
            case PowerAction::Shutdown: flags |= EWX_SHUTDOWN; break;
            case PowerAction::Restart:  flags |= EWX_REBOOT;   break;
            case PowerAction::Logoff:   flags |= EWX_LOGOFF;   break;
        }
        return ExitWindowsEx(flags, SHTDN_REASON_MINOR_OTHER) != 0;
    }

} // namespace System

// ============================================================
//  SECTION 10 — Registry Utilities
// ============================================================
namespace Registry {

    /// Read a string value from the registry
    inline std::optional<std::string> ReadString(HKEY root, const std::string& subkey, const std::string& name) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return std::nullopt;
        wchar_t buf[4096] = {};
        DWORD sz = sizeof(buf);
        DWORD type = REG_SZ;
        LSTATUS r = RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
        RegCloseKey(hk);
        if (r != ERROR_SUCCESS) return std::nullopt;
        return Str::ToNarrow(buf);
    }

    /// Write a string value to the registry
    inline bool WriteString(HKEY root, const std::string& subkey, const std::string& name, const std::string& value) {
        HKEY hk;
        if (RegCreateKeyExW(root, Str::ToWide(subkey).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hk, nullptr) != ERROR_SUCCESS)
            return false;
        std::wstring wval = Str::ToWide(value);
        LSTATUS r = RegSetValueExW(hk, Str::ToWide(name).c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(wval.c_str()), static_cast<DWORD>((wval.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
        return r == ERROR_SUCCESS;
    }

    /// Delete a registry value
    inline bool DeleteValue(HKEY root, const std::string& subkey, const std::string& name) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_WRITE, &hk) != ERROR_SUCCESS)
            return false;
        LSTATUS r = RegDeleteValueW(hk, Str::ToWide(name).c_str());
        RegCloseKey(hk);
        return r == ERROR_SUCCESS;
    }

    /// Add app to Windows startup (current user)
    inline bool AddToStartup(const std::string& appName, const std::string& exePath) {
        return WriteString(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", appName, exePath);
    }

    /// Remove app from Windows startup
    inline bool RemoveFromStartup(const std::string& appName) {
        return DeleteValue(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", appName);
    }

    // ----------------------------------------------------------
    //  Extended Registry — Read/Write all value types
    // ----------------------------------------------------------

    /// Read a DWORD value
    inline std::optional<DWORD> ReadDWORD(HKEY root, const std::string& subkey, const std::string& name) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return std::nullopt;
        DWORD val = 0, sz = sizeof(DWORD), type = REG_DWORD;
        LSTATUS r = RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, &type,
            reinterpret_cast<LPBYTE>(&val), &sz);
        RegCloseKey(hk);
        if (r != ERROR_SUCCESS) return std::nullopt;
        return val;
    }

    /// Write a DWORD value
    inline bool WriteDWORD(HKEY root, const std::string& subkey, const std::string& name, DWORD value) {
        HKEY hk;
        if (RegCreateKeyExW(root, Str::ToWide(subkey).c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hk, nullptr) != ERROR_SUCCESS)
            return false;
        LSTATUS r = RegSetValueExW(hk, Str::ToWide(name).c_str(), 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(DWORD));
        RegCloseKey(hk);
        return r == ERROR_SUCCESS;
    }

    /// Read a QWORD (64-bit) value
    inline std::optional<uint64_t> ReadQWORD(HKEY root, const std::string& subkey, const std::string& name) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return std::nullopt;
        uint64_t val = 0; DWORD sz = sizeof(val), type = REG_QWORD;
        LSTATUS r = RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, &type,
            reinterpret_cast<LPBYTE>(&val), &sz);
        RegCloseKey(hk);
        if (r != ERROR_SUCCESS) return std::nullopt;
        return val;
    }

    /// Write a QWORD (64-bit) value
    inline bool WriteQWORD(HKEY root, const std::string& subkey, const std::string& name, uint64_t value) {
        HKEY hk;
        if (RegCreateKeyExW(root, Str::ToWide(subkey).c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hk, nullptr) != ERROR_SUCCESS)
            return false;
        LSTATUS r = RegSetValueExW(hk, Str::ToWide(name).c_str(), 0, REG_QWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(uint64_t));
        RegCloseKey(hk);
        return r == ERROR_SUCCESS;
    }

    /// Read raw binary data
    inline std::optional<std::vector<BYTE>> ReadBinary(HKEY root, const std::string& subkey, const std::string& name) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return std::nullopt;
        DWORD sz = 0;
        RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, nullptr, nullptr, &sz);
        std::vector<BYTE> buf(sz);
        LSTATUS r = RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, nullptr, buf.data(), &sz);
        RegCloseKey(hk);
        if (r != ERROR_SUCCESS) return std::nullopt;
        return buf;
    }

    /// Write raw binary data
    inline bool WriteBinary(HKEY root, const std::string& subkey, const std::string& name,
                            const std::vector<BYTE>& data) {
        HKEY hk;
        if (RegCreateKeyExW(root, Str::ToWide(subkey).c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hk, nullptr) != ERROR_SUCCESS)
            return false;
        LSTATUS r = RegSetValueExW(hk, Str::ToWide(name).c_str(), 0, REG_BINARY,
            data.data(), static_cast<DWORD>(data.size()));
        RegCloseKey(hk);
        return r == ERROR_SUCCESS;
    }

    /// Read a MULTI_SZ (list of strings) value
    inline std::vector<std::string> ReadMultiString(HKEY root, const std::string& subkey, const std::string& name) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return {};
        DWORD sz = 0;
        RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, nullptr, nullptr, &sz);
        std::vector<wchar_t> buf(sz / sizeof(wchar_t) + 2, L'\0');
        RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, nullptr,
            reinterpret_cast<LPBYTE>(buf.data()), &sz);
        RegCloseKey(hk);
        std::vector<std::string> result;
        for (const wchar_t* p = buf.data(); *p; p += wcslen(p) + 1)
            result.push_back(Str::ToNarrow(p));
        return result;
    }

    // ----------------------------------------------------------
    //  Key Management
    // ----------------------------------------------------------

    /// Check if a registry key exists
    inline bool KeyExists(HKEY root, const std::string& subkey) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return false;
        RegCloseKey(hk);
        return true;
    }

    /// Check if a registry value exists
    inline bool ValueExists(HKEY root, const std::string& subkey, const std::string& name) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return false;
        LSTATUS r = RegQueryValueExW(hk, Str::ToWide(name).c_str(), nullptr, nullptr, nullptr, nullptr);
        RegCloseKey(hk);
        return r == ERROR_SUCCESS;
    }

    /// Create a registry key (does nothing if it already exists)
    inline bool CreateKey(HKEY root, const std::string& subkey) {
        HKEY hk;
        LSTATUS r = RegCreateKeyExW(root, Str::ToWide(subkey).c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hk, nullptr);
        if (r == ERROR_SUCCESS) RegCloseKey(hk);
        return r == ERROR_SUCCESS;
    }

    /// Delete a key and ALL its subkeys and values recursively
    /// !! DANGEROUS — there is no undo !!
    inline bool DeleteKeyRecursive(HKEY root, const std::string& subkey) {
        return RegDeleteTreeW(root, Str::ToWide(subkey).c_str()) == ERROR_SUCCESS;
    }

    /// List all value names under a key
    inline std::vector<std::string> ListValues(HKEY root, const std::string& subkey) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return {};
        std::vector<std::string> result;
        wchar_t name[16384]; DWORD nameLen = 16384; DWORD idx = 0;
        while (RegEnumValueW(hk, idx++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            result.push_back(Str::ToNarrow(name));
            nameLen = 16384;
        }
        RegCloseKey(hk);
        return result;
    }

    /// List all subkey names under a key
    inline std::vector<std::string> ListSubkeys(HKEY root, const std::string& subkey) {
        HKEY hk;
        if (RegOpenKeyExW(root, Str::ToWide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return {};
        std::vector<std::string> result;
        wchar_t name[256]; DWORD nameLen = 256; DWORD idx = 0;
        while (RegEnumKeyExW(hk, idx++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            result.push_back(Str::ToNarrow(name));
            nameLen = 256;
        }
        RegCloseKey(hk);
        return result;
    }

    /// Export a registry key to a .reg file (uses reg.exe)
    inline bool ExportKey(HKEY root, const std::string& subkey, const std::string& outputFile) {
        std::string rootName;
        if      (root == HKEY_LOCAL_MACHINE)  rootName = "HKLM";
        else if (root == HKEY_CURRENT_USER)   rootName = "HKCU";
        else if (root == HKEY_CLASSES_ROOT)   rootName = "HKCR";
        else if (root == HKEY_USERS)          rootName = "HKU";
        else if (root == HKEY_CURRENT_CONFIG) rootName = "HKCC";
        else return false;
        std::string cmd = "reg export \"" + rootName + "\\" + subkey + "\" \"" + outputFile + "\" /y";
        return Process::Run("cmd.exe", "/c " + cmd, false, true);
    }

    /// Import a .reg file into the registry (uses reg.exe, may require elevation)
    inline bool ImportRegFile(const std::string& regFile) {
        return Process::Run("cmd.exe", "/c reg import \"" + regFile + "\"", false, true);
    }

    // ----------------------------------------------------------
    //  Common Registry Shortcuts
    // ----------------------------------------------------------

    /// Get/Set Windows dark mode (0 = dark, 1 = light)
    inline bool IsLightMode() {
        auto v = ReadDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "AppsUseLightTheme");
        return v.value_or(1) == 1;
    }

    inline bool SetLightMode(bool light) {
        DWORD val = light ? 1 : 0;
        bool ok = true;
        ok &= WriteDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "AppsUseLightTheme", val);
        ok &= WriteDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "SystemUsesLightTheme", val);
        return ok;
    }

    /// Disable/enable Windows Lock Screen
    inline bool SetLockScreenEnabled(bool enabled) {
        return WriteDWORD(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
            "NoLockScreen", enabled ? 0 : 1);
    }

    /// Get/Set whether file extensions are shown in Explorer
    inline bool AreExtensionsShown() {
        auto v = ReadDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            "HideFileExt");
        return v.value_or(1) == 0;
    }

    inline bool SetShowExtensions(bool show) {
        return WriteDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            "HideFileExt", show ? 0 : 1);
    }

    /// Get/Set whether hidden files are shown in Explorer
    inline bool AreHiddenFilesShown() {
        auto v = ReadDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            "Hidden");
        return v.value_or(2) == 1;
    }

    inline bool SetShowHiddenFiles(bool show) {
        return WriteDWORD(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            "Hidden", show ? 1 : 2);
    }

    /// Register a custom file extension association
    /// e.g. RegisterFileAssociation(".xyz", "MyApp.Document", "My XYZ File", "C:\\myapp.exe,0", "C:\\myapp.exe \"%1\"")
    inline bool RegisterFileAssociation(const std::string& ext, const std::string& progId,
                                        const std::string& description, const std::string& iconPath,
                                        const std::string& openCommand) {
        bool ok = true;
        ok &= WriteString(HKEY_CLASSES_ROOT, ext, "", progId);
        ok &= WriteString(HKEY_CLASSES_ROOT, progId, "", description);
        ok &= WriteString(HKEY_CLASSES_ROOT, progId + "\\DefaultIcon", "", iconPath);
        ok &= WriteString(HKEY_CLASSES_ROOT, progId + "\\shell\\open\\command", "", openCommand);
        return ok;
    }

    /// Add a custom context menu entry for a file type
    /// e.g. AddContextMenuEntry("*", "MyAction", "Do My Thing", "C:\\myapp.exe \"%1\"")
    inline bool AddContextMenuEntry(const std::string& fileType, const std::string& verb,
                                    const std::string& label, const std::string& command) {
        std::string base = fileType + "\\shell\\" + verb;
        bool ok = true;
        ok &= WriteString(HKEY_CLASSES_ROOT, base, "", label);
        ok &= WriteString(HKEY_CLASSES_ROOT, base + "\\command", "", command);
        return ok;
    }

    /// Remove a context menu entry
    inline bool RemoveContextMenuEntry(const std::string& fileType, const std::string& verb) {
        return DeleteKeyRecursive(HKEY_CLASSES_ROOT, fileType + "\\shell\\" + verb);
    }

} // namespace Registry

// ============================================================
//  SECTION 11 — Notification / Tray (Toast-style via balloon)
// ============================================================
namespace Notify {

    /// Show a system tray balloon notification
    /// (Requires a valid HWND; uses a hidden window internally if nullptr passed)
    inline bool Balloon(const std::string& title, const std::string& text, DWORD timeoutMs = 3000, HICON icon = nullptr) {
        NOTIFYICONDATAW nid{};
        nid.cbSize           = sizeof(nid);
        nid.hWnd             = GetConsoleWindow();
        nid.uID              = 1;
        nid.uFlags           = NIF_INFO | NIF_ICON | NIF_TIP;
        nid.dwInfoFlags      = NIIF_INFO;
        nid.uTimeout         = timeoutMs;
        nid.hIcon            = icon ? icon : LoadIconW(nullptr, IDI_INFORMATION);
        wcsncpy_s(nid.szInfo,     Str::ToWide(text).c_str(),  79);
        wcsncpy_s(nid.szInfoTitle, Str::ToWide(title).c_str(), 63);
        wcsncpy_s(nid.szTip,      Str::ToWide(title).c_str(), 127);
        Shell_NotifyIconW(NIM_ADD,    &nid);
        ::Sleep(timeoutMs);
        Shell_NotifyIconW(NIM_DELETE, &nid);
        return true;
    }

} // namespace Notify

// ============================================================
//  SECTION 12 — Audio / Beep Utilities
// ============================================================
namespace Audio {

    /// Play the default system beep
    inline void Beep() { MessageBeep(MB_OK); }

    /// Play a specific system sound
    /// sound: MB_OK, MB_ICONERROR, MB_ICONWARNING, MB_ICONINFORMATION, MB_ICONQUESTION
    inline void SystemSound(UINT sound) { MessageBeep(sound); }

    /// Play a tone at a given frequency (Hz) for `ms` milliseconds
    inline void Tone(DWORD freqHz, DWORD ms) { ::Beep(freqHz, ms); }

    /// Play a WAV file asynchronously
    inline bool PlayWAV(const std::string& path) {
        return PlaySoundW(Str::ToWide(path).c_str(), nullptr, SND_FILENAME | SND_ASYNC) != 0;
    }

    /// Stop any currently playing sound
    inline void StopSound() {
        PlaySoundW(nullptr, nullptr, 0);
    }

} // namespace Audio

// ============================================================
//  SECTION 13 — Logging Utility
// ============================================================
namespace Log {

    enum class Level { DEBUG, INFO, WARNING, ERROR_LEVEL };

    struct Logger {
        std::string logPath;
        bool        echoToConsole = true;
        Level       minLevel      = Level::DEBUG;

        Logger() = default;
        explicit Logger(const std::string& path, bool echo = true, Level min = Level::DEBUG)
            : logPath(path), echoToConsole(echo), minLevel(min) {}

        void Write(Level level, const std::string& msg) {
            if (level < minLevel) return;
            static const char* names[] = { "DEBUG", "INFO", "WARN", "ERROR" };
            std::string line = "[" + System::Now() + "] [" + names[static_cast<int>(level)] + "] " + msg + "\n";
            if (echoToConsole) std::fputs(line.c_str(), stderr);
            if (!logPath.empty()) File::Append(logPath, line);
        }

        void debug(const std::string& m)   { Write(Level::DEBUG,       m); }
        void info(const std::string& m)    { Write(Level::INFO,        m); }
        void warn(const std::string& m)    { Write(Level::WARNING,     m); }
        void error(const std::string& m)   { Write(Level::ERROR_LEVEL, m); }
    };

    /// Global default logger (writes to stderr, no file)
    inline Logger& Default() {
        static Logger g;
        return g;
    }

} // namespace Log

// ============================================================
//  SECTION 14 — Hotkey Manager (global hotkeys)
// ============================================================
namespace Hotkey {

    struct HotkeyEntry {
        int                    id;
        UINT                   modifiers; // MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN
        UINT                   vk;
        std::function<void()>  callback;
    };

    inline std::vector<HotkeyEntry>& _hotkeys() {
        static std::vector<HotkeyEntry> v;
        return v;
    }

    /// Register a global hotkey. Returns assigned ID or -1 on failure.
    inline int Register(UINT modifiers, UINT vk, std::function<void()> callback) {
        static int nextId = 100;
        int id = nextId++;
        if (!RegisterHotKey(nullptr, id, modifiers, vk)) return -1;
        _hotkeys().push_back({ id, modifiers, vk, std::move(callback) });
        return id;
    }

    /// Unregister all hotkeys
    inline void UnregisterAll() {
        for (auto& h : _hotkeys())
            UnregisterHotKey(nullptr, h.id);
        _hotkeys().clear();
    }

    /// Process hotkey messages (call in a message loop)
    /// Returns true if the message was a hotkey and was dispatched.
    inline bool Process(const MSG& msg) {
        if (msg.message != WM_HOTKEY) return false;
        int id = static_cast<int>(msg.wParam);
        for (auto& h : _hotkeys()) {
            if (h.id == id) { h.callback(); return true; }
        }
        return false;
    }

    /// Run a blocking hotkey loop until WM_QUIT is posted
    inline void RunLoop() {
        MSG msg{};
        while (GetMessageW(&msg, nullptr, 0, 0)) {
            if (!Process(msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        UnregisterAll();
    }

} // namespace Hotkey

// ============================================================
//  SECTION 15 — Screen / Screenshot
// ============================================================
namespace Screen {

    /// Capture the entire screen into an HBITMAP (caller must DeleteObject)
    inline HBITMAP Capture(int x = 0, int y = 0, int w = 0, int h = 0) {
        if (w == 0) w = GetSystemMetrics(SM_CXSCREEN);
        if (h == 0) h = GetSystemMetrics(SM_CYSCREEN);
        HDC hScreen  = GetDC(nullptr);
        HDC hDC      = CreateCompatibleDC(hScreen);
        HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
        SelectObject(hDC, hBmp);
        BitBlt(hDC, 0, 0, w, h, hScreen, x, y, SRCCOPY);
        DeleteDC(hDC);
        ReleaseDC(nullptr, hScreen);
        return hBmp;
    }

    /// Get the color of a specific pixel on screen
    inline COLORREF GetPixelColor(int x, int y) {
        HDC hdc  = GetDC(nullptr);
        COLORREF c = ::GetPixel(hdc, x, y);
        ReleaseDC(nullptr, hdc);
        return c;
    }

    /// Get R, G, B components of a pixel
    inline std::tuple<int,int,int> GetPixelRGB(int x, int y) {
        COLORREF c = GetPixelColor(x, y);
        return { GetRValue(c), GetGValue(c), GetBValue(c) };
    }

    /// Save a screen region to a .bmp file
    inline bool SaveBMP(const std::string& path, int x = 0, int y = 0, int w = 0, int h = 0) {
        if (w == 0) w = GetSystemMetrics(SM_CXSCREEN);
        if (h == 0) h = GetSystemMetrics(SM_CYSCREEN);
        HBITMAP hBmp = Capture(x, y, w, h);
        if (!hBmp) return false;
        BITMAP bmp{};
        GetObject(hBmp, sizeof(BITMAP), &bmp);
        BITMAPFILEHEADER bfh{};
        BITMAPINFOHEADER bih{};
        bih.biSize        = sizeof(BITMAPINFOHEADER);
        bih.biWidth       = bmp.bmWidth;
        bih.biHeight      = bmp.bmHeight;
        bih.biPlanes      = 1;
        bih.biBitCount    = 24;
        bih.biCompression = BI_RGB;
        DWORD rowSize     = ((bmp.bmWidth * 3 + 3) & ~3);
        bih.biSizeImage   = rowSize * bmp.bmHeight;
        bfh.bfType        = 0x4D42;
        bfh.bfOffBits     = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        bfh.bfSize        = bfh.bfOffBits + bih.biSizeImage;
        std::vector<BYTE> pixels(bih.biSizeImage);
        HDC hdc = GetDC(nullptr);
        BITMAPINFO bi{}; bi.bmiHeader = bih;
        GetDIBits(hdc, hBmp, 0, bmp.bmHeight, pixels.data(), &bi, DIB_RGB_COLORS);
        ReleaseDC(nullptr, hdc);
        DeleteObject(hBmp);
        std::ofstream f(path, std::ios::binary);
        if (!f) return false;
        f.write(reinterpret_cast<char*>(&bfh), sizeof(bfh));
        f.write(reinterpret_cast<char*>(&bih),  sizeof(bih));
        f.write(reinterpret_cast<char*>(pixels.data()), pixels.size());
        return f.good();
    }

    /// Scan screen for the first pixel matching a color within tolerance.
    /// Returns {x, y} or {-1,-1} if not found.
    inline std::pair<int,int> FindColor(COLORREF target, int tolerance = 10,
                                        int x0 = 0, int y0 = 0, int x1 = 0, int y1 = 0) {
        if (x1 == 0) x1 = GetSystemMetrics(SM_CXSCREEN);
        if (y1 == 0) y1 = GetSystemMetrics(SM_CYSCREEN);
        HDC hdc = GetDC(nullptr);
        int tr = GetRValue(target), tg = GetGValue(target), tb = GetBValue(target);
        for (int y = y0; y < y1; ++y) {
            for (int x = x0; x < x1; ++x) {
                COLORREF c = ::GetPixel(hdc, x, y);
                if (std::abs((int)GetRValue(c) - tr) <= tolerance &&
                    std::abs((int)GetGValue(c) - tg) <= tolerance &&
                    std::abs((int)GetBValue(c) - tb) <= tolerance) {
                    ReleaseDC(nullptr, hdc);
                    return { x, y };
                }
            }
        }
        ReleaseDC(nullptr, hdc);
        return { -1, -1 };
    }

} // namespace Screen

// ============================================================
//  SECTION 16 — Net Utilities
// ============================================================
namespace Net {

    /// Perform an HTTP GET request. Returns response body or nullopt on failure.
    inline std::optional<std::string> HttpGet(const std::string& url, DWORD timeoutMs = 10000) {
        HINTERNET hInet = InternetOpenW(L"WinUtils/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInet) return std::nullopt;
        HINTERNET hUrl = InternetOpenUrlW(hInet, Str::ToWide(url).c_str(), nullptr, 0,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hUrl) { InternetCloseHandle(hInet); return std::nullopt; }
        std::string result;
        char buf[4096];
        DWORD bytesRead = 0;
        while (InternetReadFile(hUrl, buf, sizeof(buf), &bytesRead) && bytesRead)
            result.append(buf, bytesRead);
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInet);
        return result;
    }

    /// Perform an HTTP POST request with a body. Returns response body or nullopt.
    inline std::optional<std::string> HttpPost(const std::string& url, const std::string& body,
                                                const std::string& contentType = "application/x-www-form-urlencoded") {
        // Parse URL
        URL_COMPONENTSW uc{};
        uc.dwStructSize = sizeof(uc);
        wchar_t host[256] = {}, path[1024] = {};
        uc.lpszHostName     = host; uc.dwHostNameLength   = 256;
        uc.lpszUrlPath      = path; uc.dwUrlPathLength    = 1024;
        std::wstring wurl = Str::ToWide(url);
        if (!InternetCrackUrlW(wurl.c_str(), 0, 0, &uc)) return std::nullopt;
        HINTERNET hInet = InternetOpenW(L"WinUtils/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInet) return std::nullopt;
        HINTERNET hConn = InternetConnectW(hInet, host, uc.nPort, nullptr, nullptr,
            INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConn) { InternetCloseHandle(hInet); return std::nullopt; }
        HINTERNET hReq = HttpOpenRequestW(hConn, L"POST", path, nullptr, nullptr, nullptr,
            (uc.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_FLAG_SECURE : 0) | INTERNET_FLAG_RELOAD, 0);
        if (!hReq) { InternetCloseHandle(hConn); InternetCloseHandle(hInet); return std::nullopt; }
        std::wstring wct = Str::ToWide("Content-Type: " + contentType);
        HttpAddRequestHeadersW(hReq, wct.c_str(), static_cast<DWORD>(wct.size()), HTTP_ADDREQ_FLAG_ADD);
        HttpSendRequestW(hReq, nullptr, 0, const_cast<char*>(body.c_str()), static_cast<DWORD>(body.size()));
        std::string result;
        char buf[4096]; DWORD bytesRead = 0;
        while (InternetReadFile(hReq, buf, sizeof(buf), &bytesRead) && bytesRead)
            result.append(buf, bytesRead);
        InternetCloseHandle(hReq); InternetCloseHandle(hConn); InternetCloseHandle(hInet);
        return result;
    }

    /// Download a file from a URL to a local path. Returns true on success.
    inline bool DownloadFile(const std::string& url, const std::string& destPath) {
        auto data = HttpGet(url);
        if (!data) return false;
        std::ofstream f(destPath, std::ios::binary);
        if (!f) return false;
        f.write(data->data(), data->size());
        return f.good();
    }

    /// Get the local machine's primary IPv4 address as a string.
    inline std::string GetLocalIP() {
        char hostname[256] = {};
        if (gethostname(hostname, sizeof(hostname)) != 0) return "127.0.0.1";
        // Use WinInet approach — no Winsock link required for a basic lookup
        auto result = Process::RunCapture("powershell -Command \"(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1).IPAddress\"");
        if (result) return Str::Trim(*result);
        return "127.0.0.1";
    }

    /// Check if there is an active internet connection
    inline bool IsConnected() {
        DWORD flags = 0;
        return InternetGetConnectedState(&flags, 0) != FALSE;
    }

} // namespace Net

// ============================================================
//  SECTION 17 — Crypto Utilities
// ============================================================
namespace Crypto {

    /// Simple XOR obfuscation (not cryptographically secure, but handy for configs)
    inline std::string XorObfuscate(const std::string& data, const std::string& key) {
        std::string result = data;
        for (size_t i = 0; i < data.size(); ++i)
            result[i] = data[i] ^ key[i % key.size()];
        return result;
    }

    /// Compute SHA-256 hash of a string using Windows CNG. Returns hex string.
    inline std::string SHA256(const std::string& data) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS status;
        std::string hexResult;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return {};
        DWORD hashLen = 0, cbData = 0;
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(DWORD), &cbData, 0);
        std::vector<BYTE> hashBuf(hashLen);
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return {};
        }
        BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.c_str())), static_cast<ULONG>(data.size()), 0);
        BCryptFinishHash(hHash, hashBuf.data(), hashLen, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        char hex[3];
        for (BYTE b : hashBuf) { std::snprintf(hex, sizeof(hex), "%02x", b); hexResult += hex; }
        return hexResult;
    }


    /// Compute MD5 hash of a string using Windows CNG. Returns hex string.
    inline std::string MD5(const std::string& data) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::string hexResult;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, nullptr, 0) != 0) return {};
        DWORD hashLen = 0, cbData = 0;
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(DWORD), &cbData, 0);
        std::vector<BYTE> hashBuf(hashLen);
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return {};
        }
        BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.c_str())), static_cast<ULONG>(data.size()), 0);
        BCryptFinishHash(hHash, hashBuf.data(), hashLen, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        char hex[3];
        for (BYTE b : hashBuf) { std::snprintf(hex, sizeof(hex), "%02x", b); hexResult += hex; }
        return hexResult;
    }

    /// Base64 encode a string (no external libs)
    inline std::string Base64Encode(const std::string& input) {
        static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val = 0, bits = -6;
        for (unsigned char c : input) {
            val = (val << 8) + c; bits += 8;
            while (bits >= 0) { out += table[(val >> bits) & 0x3F]; bits -= 6; }
        }
        if (bits > -6) out += table[((val << 8) >> (bits + 8)) & 0x3F];
        while (out.size() % 4) out += '=';
        return out;
    }

    /// Base64 decode a string
    inline std::string Base64Decode(const std::string& input) {
        static const int T[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
        };
        std::string out; int val = 0, bits = -8;
        for (unsigned char c : input) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c]; bits += 6;
            if (bits >= 0) { out += static_cast<char>((val >> bits) & 0xFF); bits -= 8; }
        }
        return out;
    }

} // namespace Crypto

// ============================================================
//  SECTION 18 — INI File Utilities
// ============================================================
namespace Ini {

    /// Read a string value from an INI file
    inline std::string Read(const std::string& file, const std::string& section,
                            const std::string& key, const std::string& defaultVal = "") {
        wchar_t buf[1024] = {};
        GetPrivateProfileStringW(Str::ToWide(section).c_str(), Str::ToWide(key).c_str(),
            Str::ToWide(defaultVal).c_str(), buf, 1024, Str::ToWide(file).c_str());
        return Str::ToNarrow(buf);
    }

    /// Read an integer value from an INI file
    inline int ReadInt(const std::string& file, const std::string& section,
                       const std::string& key, int defaultVal = 0) {
        return static_cast<int>(GetPrivateProfileIntW(Str::ToWide(section).c_str(),
            Str::ToWide(key).c_str(), defaultVal, Str::ToWide(file).c_str()));
    }

    /// Write a string value to an INI file
    inline bool Write(const std::string& file, const std::string& section,
                      const std::string& key, const std::string& value) {
        return WritePrivateProfileStringW(Str::ToWide(section).c_str(), Str::ToWide(key).c_str(),
            Str::ToWide(value).c_str(), Str::ToWide(file).c_str()) != 0;
    }

    /// Write an integer value to an INI file
    inline bool WriteInt(const std::string& file, const std::string& section,
                         const std::string& key, int value) {
        return Write(file, section, key, std::to_string(value));
    }

    /// Delete a key from an INI file
    inline bool DeleteKey(const std::string& file, const std::string& section, const std::string& key) {
        return WritePrivateProfileStringW(Str::ToWide(section).c_str(), Str::ToWide(key).c_str(),
            nullptr, Str::ToWide(file).c_str()) != 0;
    }

    /// Delete an entire section from an INI file
    inline bool DeleteSection(const std::string& file, const std::string& section) {
        return WritePrivateProfileStringW(Str::ToWide(section).c_str(), nullptr,
            nullptr, Str::ToWide(file).c_str()) != 0;
    }

} // namespace Ini

// ============================================================
//  SECTION 19 — Console Utilities
// ============================================================
namespace Console {

    /// Set console text color. fg/bg are FOREGROUND_*/BACKGROUND_* constants.
    inline void SetColor(WORD fg = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
                         WORD bg = 0) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), fg | bg);
    }

    /// Reset console color to default white on black
    inline void ResetColor() {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    /// Clear the console screen
    inline void Clear() {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi{};
        GetConsoleScreenBufferInfo(h, &csbi);
        DWORD size = csbi.dwSize.X * csbi.dwSize.Y;
        DWORD written = 0;
        COORD origin = { 0, 0 };
        FillConsoleOutputCharacterW(h, L' ', size, origin, &written);
        FillConsoleOutputAttribute(h, csbi.wAttributes, size, origin, &written);
        SetConsoleCursorPosition(h, origin);
    }

    /// Set the console window title
    inline void SetTitle(const std::string& title) {
        SetConsoleTitleW(Str::ToWide(title).c_str());
    }

    /// Move the console cursor to (x, y)
    inline void SetCursorPos(SHORT x, SHORT y) {
        SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), { x, y });
    }

    /// Show or hide the console cursor
    inline void ShowCursor(bool visible) {
        CONSOLE_CURSOR_INFO cci{};
        GetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cci);
        cci.bVisible = visible;
        SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cci);
    }

    /// Resize the console window (columns x rows)
    inline void SetSize(SHORT cols, SHORT rows) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        COORD size = { cols, rows };
        SetConsoleScreenBufferSize(h, size);
        SMALL_RECT rect = { 0, 0, static_cast<SHORT>(cols - 1), static_cast<SHORT>(rows - 1) };
        SetConsoleWindowInfo(h, TRUE, &rect);
    }

    /// Print colored text then reset
    inline void PrintColor(const std::string& text, WORD color = FOREGROUND_GREEN | FOREGROUND_INTENSITY) {
        SetColor(color);
        std::fputs(text.c_str(), stdout);
        ResetColor();
    }

    /// Print a horizontal rule across the console
    inline void PrintRule(char ch = '-', int width = 80) {
        std::string line(width, ch);
        line += '\n';
        std::fputs(line.c_str(), stdout);
    }

} // namespace Console

// ============================================================
//  SECTION 20 — Taskbar Progress (ITaskbarList3)
// ============================================================
namespace Progress {

#ifndef __ITaskbarList3_INTERFACE_DEFINED__
    // Minimal definition if not available in older SDKs
    typedef enum TBPFLAG {
        TBPF_NOPROGRESS    = 0,
        TBPF_INDETERMINATE = 0x1,
        TBPF_NORMAL        = 0x2,
        TBPF_ERROR         = 0x4,
        TBPF_PAUSED        = 0x8
    } TBPFLAG;
#endif

    /// RAII wrapper for taskbar progress bar (Windows 7+)
    struct TaskbarProgress {
        ITaskbarList3* pTbl = nullptr;
        HWND hwnd = nullptr;

        explicit TaskbarProgress(HWND targetHwnd = nullptr) {
            CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            CoCreateInstance(CLSID_TaskbarList, nullptr, CLSCTX_ALL,
                __uuidof(ITaskbarList3), reinterpret_cast<void**>(&pTbl));
            hwnd = targetHwnd ? targetHwnd : GetConsoleWindow();
            if (pTbl) pTbl->HrInit();
        }
        ~TaskbarProgress() {
            if (pTbl) { pTbl->SetProgressState(hwnd, TBPF_NOPROGRESS); pTbl->Release(); }
        }

        /// Set progress 0-100
        void Set(ULONGLONG value, ULONGLONG total = 100) {
            if (pTbl) pTbl->SetProgressValue(hwnd, value, total);
        }

        void SetState(TBPFLAG state) {
            if (pTbl) pTbl->SetProgressState(hwnd, state);
        }

        void SetIndeterminate() { SetState(TBPF_INDETERMINATE); }
        void SetError()         { SetState(TBPF_ERROR);         }
        void SetPaused()        { SetState(TBPF_PAUSED);        }
        void SetNormal()        { SetState(TBPF_NORMAL);        }
        void Clear()            { SetState(TBPF_NOPROGRESS);    }
    };

} // namespace Progress

// ============================================================
//  SECTION 21 — System Extras
// ============================================================
namespace System {

    // (extends existing System namespace)

    /// Check if the current process is running as Administrator
    inline bool IsAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(nullptr, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        return isAdmin != FALSE;
    }

    /// Get all available drive letters (e.g. {"C:\\", "D:\\"})
    inline std::vector<std::string> GetDrives() {
        std::vector<std::string> drives;
        DWORD mask = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (mask & (1 << i)) {
                std::string d = " :\\";
                d[0] = static_cast<char>('A' + i);
                drives.push_back(d);
            }
        }
        return drives;
    }

    /// Get battery status. Returns {percent, isCharging}. {-1, false} if no battery.
    inline std::pair<int, bool> GetBatteryStatus() {
        SYSTEM_POWER_STATUS sps{};
        if (!GetSystemPowerStatus(&sps)) return { -1, false };
        if (sps.BatteryLifePercent == 255) return { -1, false }; // no battery
        return { static_cast<int>(sps.BatteryLifePercent), (sps.ACLineStatus == 1) };
    }

    /// Relaunch the current executable as Administrator
    inline bool RelaunchAsAdmin() {
        wchar_t exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        SHELLEXECUTEINFOW sei{};
        sei.cbSize  = sizeof(sei);
        sei.lpVerb  = L"runas";
        sei.lpFile  = exe;
        sei.nShow   = SW_SHOWNORMAL;
        return ShellExecuteExW(&sei) != FALSE;
    }

} // namespace System

// ============================================================
//  SECTION 22 — File Extras
// ============================================================
namespace File {

    /// Create multiple files at once from a list of {path, content} pairs
    inline int CreateMany(const std::vector<std::pair<std::string, std::string>>& files) {
        int count = 0;
        for (auto& [path, content] : files)
            if (Create(path, content)) ++count;
        return count; // returns number successfully created
    }

    /// Watch a directory for changes. Calls onChange() when a change is detected.
    /// Runs in the calling thread — call from a dedicated thread.
    /// Set *running = false from another thread to stop.
    inline void Watch(const std::string& dir, std::function<void(const std::string&)> onChange,
                      bool* running = nullptr) {
        HANDLE hDir = CreateFileW(Str::ToWide(dir).c_str(), FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
        if (hDir == INVALID_HANDLE_VALUE) return;
        std::vector<BYTE> buf(65536);
        OVERLAPPED ov{};
        ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        static bool _defaultRunning = true;
        if (!running) running = &_defaultRunning;
        while (*running) {
            DWORD bytesReturned = 0;
            ResetEvent(ov.hEvent);
            ReadDirectoryChangesW(hDir, buf.data(), static_cast<DWORD>(buf.size()), TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                &bytesReturned, &ov, nullptr);
            if (WaitForSingleObject(ov.hEvent, 500) == WAIT_OBJECT_0) {
                GetOverlappedResult(hDir, &ov, &bytesReturned, FALSE);
                auto* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buf.data());
                do {
                    std::wstring wname(info->FileName, info->FileNameLength / sizeof(wchar_t));
                    onChange(dir + "\\" + Str::ToNarrow(wname));
                    if (!info->NextEntryOffset) break;
                    info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                        reinterpret_cast<BYTE*>(info) + info->NextEntryOffset);
                } while (true);
            }
        }
        CloseHandle(ov.hEvent);
        CloseHandle(hDir);
    }

} // namespace File

// ============================================================
//  SECTION 23 — Mouse Record & Replay
// ============================================================
namespace Mouse {

    struct MouseEvent {
        DWORD type;    // MOUSEEVENTF_MOVE, MOUSEEVENTF_LEFTDOWN, etc.
        int   x, y;
        DWORD delayMs; // delay after this event
    };

    inline std::vector<MouseEvent>& _recording() {
        static std::vector<MouseEvent> v;
        return v;
    }
    inline bool& _isRecording() { static bool b = false; return b; }
    inline std::chrono::steady_clock::time_point& _lastTime() {
        static auto t = std::chrono::steady_clock::now(); return t;
    }

    /// Start recording mouse events. Call StopRecording() to end.
    inline void StartRecording() {
        _recording().clear();
        _isRecording() = true;
        _lastTime()    = std::chrono::steady_clock::now();
    }

    /// Record a single frame (call repeatedly, e.g. in a timer loop at ~60Hz)
    inline void RecordFrame() {
        if (!_isRecording()) return;
        POINT p = GetPos();
        auto now   = std::chrono::steady_clock::now();
        DWORD delay = static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(now - _lastTime()).count());
        _lastTime() = now;
        _recording().push_back({ MOUSEEVENTF_MOVE, p.x, p.y, delay });
    }

    /// Stop recording and return the recorded events
    inline std::vector<MouseEvent> StopRecording() {
        _isRecording() = false;
        return _recording();
    }

    /// Replay a previously recorded sequence
    inline void Replay(const std::vector<MouseEvent>& events, float speedMultiplier = 1.0f) {
        for (auto& e : events) {
            SetPos(e.x, e.y);
            if (e.type != MOUSEEVENTF_MOVE)
                mouse_event(e.type, 0, 0, 0, 0);
            DWORD delay = static_cast<DWORD>(e.delayMs / speedMultiplier);
            if (delay > 0) ::Sleep(delay);
        }
    }

    /// Save recorded events to a file
    inline bool SaveRecording(const std::vector<MouseEvent>& events, const std::string& path) {
        std::ofstream f(path, std::ios::binary);
        if (!f) return false;
        size_t count = events.size();
        f.write(reinterpret_cast<const char*>(&count), sizeof(count));
        f.write(reinterpret_cast<const char*>(events.data()), count * sizeof(MouseEvent));
        return f.good();
    }

    /// Load recorded events from a file
    inline std::vector<MouseEvent> LoadRecording(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return {};
        size_t count = 0;
        f.read(reinterpret_cast<char*>(&count), sizeof(count));
        std::vector<MouseEvent> events(count);
        f.read(reinterpret_cast<char*>(events.data()), count * sizeof(MouseEvent));
        return events;
    }

} // namespace Mouse

// ============================================================
//  SECTION 24 — Tray Icon
// ============================================================
namespace Tray {

    // Forward declaration of internal window proc
    inline LRESULT CALLBACK _TrayWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

    struct TrayIcon {
        NOTIFYICONDATAW nid{};
        HWND            hwnd    = nullptr;
        HMENU           hMenu   = nullptr;
        std::map<UINT, std::function<void()>> menuCallbacks;
        std::function<void()> onLeftClick;
        bool            created = false;

        TrayIcon() = default;

        /// Initialize with a tooltip text and optional icon
        bool Init(const std::string& tooltip, HICON icon = nullptr) {
            // Create a hidden message-only window
            WNDCLASSEXW wc{};
            wc.cbSize        = sizeof(wc);
            wc.lpfnWndProc   = _TrayWndProc;
            wc.hInstance     = GetModuleHandleW(nullptr);
            wc.lpszClassName = L"WinUtilsTray";
            RegisterClassExW(&wc);
            hwnd = CreateWindowExW(0, L"WinUtilsTray", L"", 0, 0, 0, 0, 0,
                HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
            nid.cbSize           = sizeof(nid);
            nid.hWnd             = hwnd;
            nid.uID              = 1;
            nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE;
            nid.uCallbackMessage = WM_APP + 1;
            nid.hIcon            = icon ? icon : LoadIconW(nullptr, IDI_APPLICATION);
            wcsncpy_s(nid.szTip, Str::ToWide(tooltip).c_str(), 127);
            created = Shell_NotifyIconW(NIM_ADD, &nid) != FALSE;
            hMenu   = CreatePopupMenu();
            return created;
        }

        /// Add a menu item with a callback
        void AddMenuItem(const std::string& label, std::function<void()> cb, UINT id = 0) {
            static UINT nextId = 2000;
            if (id == 0) id = nextId++;
            AppendMenuW(hMenu, MF_STRING, id, Str::ToWide(label).c_str());
            menuCallbacks[id] = std::move(cb);
        }

        /// Add a separator line
        void AddSeparator() { AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr); }

        /// Set callback for left click on the tray icon
        void OnLeftClick(std::function<void()> cb) { onLeftClick = std::move(cb); }

        /// Update the tooltip text
        void SetTooltip(const std::string& tip) {
            wcsncpy_s(nid.szTip, Str::ToWide(tip).c_str(), 127);
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }

        /// Run the tray message loop (blocking)
        void RunLoop() {
            MSG msg{};
            while (GetMessageW(&msg, nullptr, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        /// Remove the tray icon and destroy
        void Destroy() {
            if (created) Shell_NotifyIconW(NIM_DELETE, &nid);
            if (hMenu)   DestroyMenu(hMenu);
            if (hwnd)    DestroyWindow(hwnd);
            created = false;
        }

        ~TrayIcon() { Destroy(); }
    };

    inline LRESULT CALLBACK _TrayWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        TrayIcon* tray = reinterpret_cast<TrayIcon*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_APP + 1 && tray) {
            if (lp == WM_LBUTTONUP && tray->onLeftClick)
                tray->onLeftClick();
            if (lp == WM_RBUTTONUP) {
                POINT p{}; GetCursorPos(&p);
                SetForegroundWindow(hwnd);
                UINT cmd = TrackPopupMenu(tray->hMenu, TPM_RETURNCMD | TPM_NONOTIFY, p.x, p.y, 0, hwnd, nullptr);
                if (cmd && tray->menuCallbacks.count(cmd))
                    tray->menuCallbacks[cmd]();
            }
        }
        if (msg == WM_COMMAND && tray && tray->menuCallbacks.count(static_cast<UINT>(wp)))
            tray->menuCallbacks[static_cast<UINT>(wp)]();
        if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

} // namespace Tray

// ============================================================
//  SECTION 31 — Drive Utilities
// ============================================================
namespace Drive {

    enum class DriveType { Unknown, NoRoot, Removable, Fixed, Remote, CDROM, RAMDisk };

    inline DriveType GetType(const std::string& root) {
        switch (GetDriveTypeW(Str::ToWide(root).c_str())) {
            case DRIVE_REMOVABLE: return DriveType::Removable;
            case DRIVE_FIXED:     return DriveType::Fixed;
            case DRIVE_REMOTE:    return DriveType::Remote;
            case DRIVE_CDROM:     return DriveType::CDROM;
            case DRIVE_RAMDISK:   return DriveType::RAMDisk;
            case DRIVE_NO_ROOT_DIR: return DriveType::NoRoot;
            default:              return DriveType::Unknown;
        }
    }

    /// Get free and total space on a drive in bytes
    inline std::pair<uint64_t,uint64_t> GetSpace(const std::string& root) {
        ULARGE_INTEGER free{}, total{};
        GetDiskFreeSpaceExW(Str::ToWide(root).c_str(), &free, &total, nullptr);
        return { free.QuadPart, total.QuadPart };
    }

    /// Get free space in GB
    inline double GetFreeGB(const std::string& root) {
        return static_cast<double>(GetSpace(root).first) / (1024.0*1024*1024);
    }

    /// Get total size in GB
    inline double GetTotalGB(const std::string& root) {
        return static_cast<double>(GetSpace(root).second) / (1024.0*1024*1024);
    }

    /// Get volume label for a drive
    inline std::string GetLabel(const std::string& root) {
        wchar_t label[256] = {};
        GetVolumeInformationW(Str::ToWide(root).c_str(), label, 256,
            nullptr, nullptr, nullptr, nullptr, 0);
        return Str::ToNarrow(label);
    }

    /// Set volume label for a drive (requires Admin for system drives)
    inline bool SetLabel(const std::string& root, const std::string& label) {
        return SetVolumeLabelW(Str::ToWide(root).c_str(),
            Str::ToWide(label).c_str()) != FALSE;
    }

    /// Get filesystem type (e.g. "NTFS", "FAT32", "exFAT")
    inline std::string GetFilesystem(const std::string& root) {
        wchar_t fs[64] = {};
        GetVolumeInformationW(Str::ToWide(root).c_str(), nullptr, 0,
            nullptr, nullptr, nullptr, fs, 64);
        return Str::ToNarrow(fs);
    }

    /// List all available drive roots (e.g. "C:\\", "D:\\")
    inline std::vector<std::string> ListAll() {
        std::vector<std::string> result;
        DWORD mask = GetLogicalDrives();
        for (int i = 0; i < 26; ++i)
            if (mask & (1 << i)) {
                std::string d = " :\\";
                d[0] = static_cast<char>('A' + i);
                result.push_back(d);
            }
        return result;
    }

    /// Eject a removable drive (USB, CD, etc.)
    inline bool Eject(const std::string& root) {
        std::string path = "\\.\\" + root.substr(0,2);
        HANDLE h = CreateFileW(Str::ToWide(path).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD bytes = 0;
        DeviceIoControl(h, FSCTL_LOCK_VOLUME,   nullptr, 0, nullptr, 0, &bytes, nullptr);
        DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME,nullptr, 0, nullptr, 0, &bytes, nullptr);
        bool ok = DeviceIoControl(h, IOCTL_STORAGE_EJECT_MEDIA, nullptr, 0, nullptr, 0, &bytes, nullptr) != FALSE;
        CloseHandle(h);
        return ok;
    }

    /// Lock a volume (prevent other processes from writing to it)
    /// Returns the handle — keep it open to hold the lock, CloseHandle to release.
    inline HANDLE LockVolume(const std::string& root) {
        std::string path = "\\.\\" + root.substr(0,2);
        HANDLE h = CreateFileW(Str::ToWide(path).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
        DWORD bytes = 0;
        if (!DeviceIoControl(h, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &bytes, nullptr)) {
            CloseHandle(h); return INVALID_HANDLE_VALUE;
        }
        return h; // caller must CloseHandle(h) to unlock
    }

    /// Unlock a previously locked volume handle
    inline bool UnlockVolume(HANDLE hVolume) {
        DWORD bytes = 0;
        bool ok = DeviceIoControl(hVolume, FSCTL_UNLOCK_VOLUME,
            nullptr, 0, nullptr, 0, &bytes, nullptr) != FALSE;
        CloseHandle(hVolume);
        return ok;
    }

    /// Check if a drive is ready (media present, accessible)
    inline bool IsReady(const std::string& root) {
        ULARGE_INTEGER dummy{};
        return GetDiskFreeSpaceExW(Str::ToWide(root).c_str(),
            &dummy, &dummy, &dummy) != FALSE;
    }

    /// Open a drive in Windows Explorer
    inline void OpenInExplorer(const std::string& root) {
        ShellExecuteW(nullptr, L"open", Str::ToWide(root).c_str(),
            nullptr, nullptr, SW_SHOWNORMAL);
    }

} // namespace Drive

// ============================================================
//  SECTION 32 — File Attribute & Visibility Utilities
// ============================================================
namespace FileAttr {

    /// Hide a file or folder (sets Hidden + System attributes)
    inline bool Hide(const std::string& path) {
        DWORD attr = GetFileAttributesW(Str::ToWide(path).c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) return false;
        return SetFileAttributesW(Str::ToWide(path).c_str(),
            attr | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != FALSE;
    }

    /// Unhide a file or folder (clears Hidden + System attributes)
    inline bool Unhide(const std::string& path) {
        DWORD attr = GetFileAttributesW(Str::ToWide(path).c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) return false;
        return SetFileAttributesW(Str::ToWide(path).c_str(),
            attr & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != FALSE;
    }

    /// Check if a file/folder is hidden
    inline bool IsHidden(const std::string& path) {
        DWORD attr = GetFileAttributesW(Str::ToWide(path).c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_HIDDEN);
    }

    /// Set a file as read-only
    inline bool SetReadOnly(const std::string& path, bool readOnly = true) {
        DWORD attr = GetFileAttributesW(Str::ToWide(path).c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) return false;
        if (readOnly) attr |=  FILE_ATTRIBUTE_READONLY;
        else          attr &= ~FILE_ATTRIBUTE_READONLY;
        return SetFileAttributesW(Str::ToWide(path).c_str(), attr) != FALSE;
    }

    /// Check if a file is read-only
    inline bool IsReadOnly(const std::string& path) {
        DWORD attr = GetFileAttributesW(Str::ToWide(path).c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY);
    }

    /// Mark a file as a system file
    inline bool SetSystem(const std::string& path, bool system = true) {
        DWORD attr = GetFileAttributesW(Str::ToWide(path).c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) return false;
        if (system) attr |=  FILE_ATTRIBUTE_SYSTEM;
        else        attr &= ~FILE_ATTRIBUTE_SYSTEM;
        return SetFileAttributesW(Str::ToWide(path).c_str(), attr) != FALSE;
    }

    /// Get all attributes as a DWORD (FILE_ATTRIBUTE_* flags)
    inline DWORD GetAll(const std::string& path) {
        return GetFileAttributesW(Str::ToWide(path).c_str());
    }

    /// Set raw attribute flags
    inline bool SetAll(const std::string& path, DWORD attrs) {
        return SetFileAttributesW(Str::ToWide(path).c_str(), attrs) != FALSE;
    }

    /// Write data into an NTFS Alternate Data Stream (invisible to Explorer)
    /// e.g. WriteADS("file.txt", "secret", "hidden data here")
    inline bool WriteADS(const std::string& path, const std::string& streamName,
                          const std::string& data) {
        std::string adsPath = path + ":" + streamName;
        std::ofstream f(adsPath, std::ios::binary);
        if (!f) return false;
        f << data;
        return f.good();
    }

    /// Read data from an NTFS Alternate Data Stream
    inline std::optional<std::string> ReadADS(const std::string& path,
                                               const std::string& streamName) {
        std::string adsPath = path + ":" + streamName;
        std::ifstream f(adsPath, std::ios::binary);
        if (!f) return std::nullopt;
        return std::string(std::istreambuf_iterator<char>(f),
                           std::istreambuf_iterator<char>());
    }

    /// Delete an NTFS Alternate Data Stream
    inline bool DeleteADS(const std::string& path, const std::string& streamName) {
        std::string adsPath = path + ":" + streamName;
        return DeleteFileW(Str::ToWide(adsPath).c_str()) != FALSE;
    }

    /// Recursively hide all files in a directory
    inline int HideAll(const std::string& dir) {
        int count = 0;
        std::error_code ec;
        for (auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
            if (Hide(entry.path().string())) ++count;
        }
        return count;
    }

    /// Recursively unhide all files in a directory
    inline int UnhideAll(const std::string& dir) {
        int count = 0;
        std::error_code ec;
        for (auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
            if (Unhide(entry.path().string())) ++count;
        }
        return count;
    }

} // namespace FileAttr

// ============================================================
//  SECTION 34 — AES-256-GCM Authenticated Encryption
// ============================================================
//  AES-GCM combines encryption AND authentication in one pass.
//  Unlike AES-CBC, GCM detects tampering — if anyone modifies
//  the ciphertext even by a single bit, decryption fails with
//  an authentication error. This is the preferred mode for
//  protecting files where integrity matters (game assets,
//  anti-cheat configs, license files, etc.)
//
//  Wire format: [12 byte nonce][16 byte auth tag][ciphertext]
//  The auth tag guarantees both authenticity and integrity.
//  Wrong password or tampered file = decryption returns empty.
// ============================================================
namespace EncryptGCM {
 
    // Internal helpers shared with Encrypt namespace
    namespace _gcm {
 
        /// Derive a 32-byte AES-256 key from a password using SHA-256
        inline std::vector<BYTE> DeriveKey(const std::string& password) {
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
            DWORD hashLen = 32, cb = 0;
            BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hashLen), sizeof(DWORD), &cb, 0);
            std::vector<BYTE> key(hashLen);
            BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
            BCryptHashData(hHash,
                reinterpret_cast<PUCHAR>(const_cast<char*>(password.c_str())),
                static_cast<ULONG>(password.size()), 0);
            BCryptFinishHash(hHash, key.data(), hashLen, 0);
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return key;
        }
 
        /// Generate cryptographically secure random bytes
        inline std::vector<BYTE> RandomBytes(DWORD count) {
            std::vector<BYTE> buf(count);
            BCRYPT_ALG_HANDLE hRng = nullptr;
            BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
            BCryptGenRandom(hRng, buf.data(), count, 0);
            BCryptCloseAlgorithmProvider(hRng, 0);
            return buf;
        }
 
        /// Import a raw AES key into a CNG key handle
        inline BCRYPT_KEY_HANDLE ImportAESKey(BCRYPT_ALG_HANDLE hAlg,
                                               const std::vector<BYTE>& key) {
            DWORD blobSz = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) +
                           static_cast<DWORD>(key.size());
            std::vector<BYTE> blob(blobSz);
            auto* hdr        = reinterpret_cast<BCRYPT_KEY_DATA_BLOB_HEADER*>(blob.data());
            hdr->dwMagic     = BCRYPT_KEY_DATA_BLOB_MAGIC;
            hdr->dwVersion   = BCRYPT_KEY_DATA_BLOB_VERSION1;
            hdr->cbKeyData   = static_cast<DWORD>(key.size());
            memcpy(blob.data() + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
                key.data(), key.size());
            BCRYPT_KEY_HANDLE hKey = nullptr;
            BCryptImportKey(hAlg, nullptr, BCRYPT_KEY_DATA_BLOB,
                &hKey, nullptr, 0, blob.data(), blobSz, 0);
            return hKey;
        }
    }
 
    /// Encrypt data using AES-256-GCM.
    /// Output format: [12 byte nonce][16 byte auth tag][ciphertext]
    /// The auth tag ensures integrity — any tampering causes decryption to fail.
    inline std::vector<BYTE> EncryptData(const std::vector<BYTE>& plaintext,
                                          const std::string& password) {
        auto key   = _gcm::DeriveKey(password);
        auto nonce = _gcm::RandomBytes(12); // 96-bit nonce for GCM
 
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
 
        BCRYPT_KEY_HANDLE hKey = _gcm::ImportAESKey(hAlg, key);
 
        // Set up authenticated encryption info
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        std::vector<BYTE> tag(16); // 128-bit authentication tag
        authInfo.pbNonce     = nonce.data();
        authInfo.cbNonce     = 12;
        authInfo.pbTag       = tag.data();
        authInfo.cbTag       = 16;
        authInfo.pbAuthData  = nullptr;  // no additional authenticated data
        authInfo.cbAuthData  = 0;
 
        // Encrypt
        std::vector<BYTE> ciphertext(plaintext.size());
        DWORD cipherLen = 0;
        NTSTATUS status = BCryptEncrypt(hKey,
            const_cast<PUCHAR>(plaintext.data()),
            static_cast<ULONG>(plaintext.size()),
            &authInfo,
            nullptr, 0,  // GCM doesn't use a separate IV buffer
            ciphertext.data(),
            static_cast<ULONG>(ciphertext.size()),
            &cipherLen, 0);
 
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
 
        if (!BCRYPT_SUCCESS(status)) return {};
 
        // Pack: nonce (12) + tag (16) + ciphertext
        std::vector<BYTE> result;
        result.reserve(12 + 16 + cipherLen);
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), tag.begin(), tag.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + cipherLen);
        return result;
    }
 
    /// Decrypt data encrypted with EncryptData (AES-256-GCM).
    /// Returns empty vector if password is wrong OR if the data was tampered with.
    /// You cannot tell the difference — both look the same from outside. That's by design.
    inline std::vector<BYTE> DecryptData(const std::vector<BYTE>& data,
                                          const std::string& password) {
        // Minimum: 12 (nonce) + 16 (tag) + 1 (at least 1 byte ciphertext)
        if (data.size() < 29) return {};
 
        auto key = _gcm::DeriveKey(password);
 
        // Unpack header
        std::vector<BYTE> nonce(data.begin(), data.begin() + 12);
        std::vector<BYTE> tag(data.begin() + 12, data.begin() + 28);
        std::vector<BYTE> ciphertext(data.begin() + 28, data.end());
 
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
 
        BCRYPT_KEY_HANDLE hKey = _gcm::ImportAESKey(hAlg, key);
 
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce    = nonce.data();
        authInfo.cbNonce    = 12;
        authInfo.pbTag      = tag.data();
        authInfo.cbTag      = 16;
        authInfo.pbAuthData = nullptr;
        authInfo.cbAuthData = 0;
 
        std::vector<BYTE> plaintext(ciphertext.size());
        DWORD plainLen = 0;
        NTSTATUS status = BCryptDecrypt(hKey,
            ciphertext.data(),
            static_cast<ULONG>(ciphertext.size()),
            &authInfo,
            nullptr, 0,
            plaintext.data(),
            static_cast<ULONG>(plaintext.size()),
            &plainLen, 0);
 
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
 
        // STATUS_AUTH_TAG_MISMATCH (0xC000A002) = wrong password or tampered data
        if (!BCRYPT_SUCCESS(status)) return {};
 
        plaintext.resize(plainLen);
        return plaintext;
    }
 
    /// Encrypt a string, returns Base64-encoded ciphertext
    inline std::string EncryptString(const std::string& plaintext,
                                      const std::string& password) {
        std::vector<BYTE> data(plaintext.begin(), plaintext.end());
        auto enc = EncryptData(data, password);
        if (enc.empty()) return {};
        return Crypto::Base64Encode(std::string(enc.begin(), enc.end()));
    }
 
    /// Decrypt a Base64-encoded string. Returns empty on wrong password or tampered data.
    inline std::string DecryptString(const std::string& b64cipher,
                                      const std::string& password) {
        auto raw = Crypto::Base64Decode(b64cipher);
        std::vector<BYTE> enc(raw.begin(), raw.end());
        auto dec = DecryptData(enc, password);
        if (dec.empty()) return {};
        return std::string(dec.begin(), dec.end());
    }
 
    /// Encrypt a file with AES-256-GCM. Output: path + ".gcm" unless specified.
    /// Any tampering with the output file will cause decryption to fail.
    inline bool EncryptFile(const std::string& path,
                             const std::string& password,
                             const std::string& outputPath = "") {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        std::vector<BYTE> data(std::istreambuf_iterator<char>(f), {});
        auto enc = EncryptData(data, password);
        if (enc.empty()) return false;
        std::string dest = outputPath.empty() ? path + ".gcm" : outputPath;
        std::ofstream out(dest, std::ios::binary);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(enc.data()), enc.size());
        return out.good();
    }
 
    /// Decrypt a .gcm file. Returns false if password is wrong or file was tampered with.
    inline bool DecryptFile(const std::string& encPath,
                             const std::string& password,
                             const std::string& outputPath = "") {
        std::ifstream f(encPath, std::ios::binary);
        if (!f) return false;
        std::vector<BYTE> enc(std::istreambuf_iterator<char>(f), {});
        auto dec = DecryptData(enc, password);
        if (dec.empty()) return false; // wrong password OR tampered
        std::string dest = outputPath;
        if (dest.empty()) {
            dest = encPath;
            if (dest.size() > 4 && dest.substr(dest.size() - 4) == ".gcm")
                dest = dest.substr(0, dest.size() - 4);
            else
                dest += ".dec";
        }
        std::ofstream out(dest, std::ios::binary);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(dec.data()), dec.size());
        return out.good();
    }
 
    /// Encrypt all files in a directory with AES-256-GCM
    inline int EncryptDirectory(const std::string& dir,
                                  const std::string& password,
                                  const std::string& ext = "") {
        int count = 0;
        std::error_code ec;
        for (auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
            if (!entry.is_regular_file()) continue;
            if (!ext.empty() && entry.path().extension() != ext) continue;
            if (EncryptFile(entry.path().string(), password)) ++count;
        }
        return count;
    }
 
    /// Decrypt all .gcm files in a directory
    inline int DecryptDirectory(const std::string& dir, const std::string& password) {
        int count = 0;
        std::error_code ec;
        for (auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
            if (!entry.is_regular_file()) continue;
            if (entry.path().extension() != ".gcm") continue;
            if (DecryptFile(entry.path().string(), password)) ++count;
        }
        return count;
    }
 
    /// Verify a file's integrity without fully decrypting it.
    /// Returns true if the password is correct and the file is unmodified.
    /// Returns false if the password is wrong OR the file was tampered with.
    inline bool VerifyFile(const std::string& encPath, const std::string& password) {
        std::ifstream f(encPath, std::ios::binary);
        if (!f) return false;
        std::vector<BYTE> enc(std::istreambuf_iterator<char>(f), {});
        // DecryptData returns empty on any auth failure
        return !DecryptData(enc, password).empty();
    }
 
} // namespace EncryptGCM
 
} // namespace WinUtils
 
#endif // WIN_UTILS_HPP
 
// ============================================================
//  QUICK REFERENCE — WinUtils.hpp
// ============================================================
//  Str        Dialog        File          Mouse         Keyboard
//  Clipboard  Process       Window        System        Registry
//  Notify     Audio         Log           Hotkey        Screen
//  Net        Crypto        Ini           Console       Progress
//  Tray       Drive         FileAttr      Encrypt       EncryptGCM
// ============================================================
 
// ============================================================
//  QUICK REFERENCE — WinUtils.hpp
// ============================================================
//  Str        Dialog        File          Mouse         Keyboard
//  Clipboard  Process       Window        System        Registry
//  Notify     Audio         Log           Hotkey        Screen
//  Net        Crypto        Ini           Console       Progress
//  Tray       Drive         FileAttr      Encrypt
// ============================================================