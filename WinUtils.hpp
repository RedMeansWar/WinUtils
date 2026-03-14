// ============================================================
//  WinUtils.hpp  —  A comprehensive Windows utility header
//  Requires: Windows (Win32 API), C++17 or later
//  Usage: #include "WinUtils.hpp"
//  NOTE: Link against: user32.lib, shell32.lib, wininet.lib,
//        gdi32.lib, advapi32.lib, ole32.lib, comdlg32.lib
// ============================================================

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
#include <playsoundapi.h>

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

// ---- Pragma comments (auto-link) ----
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")

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
            << "Open \"" << Str::ReplaceAll(outPath, "\\", "\\\\") << "\" For Output As #1\n"
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

} // namespace Screen

} // namespace WinUtils

#endif // WIN_UTILS_HPP

// ============================================================
//  QUICK REFERENCE
// ============================================================
//
//  WinUtils::Str::         ToWide, ToNarrow, Format, Split, Trim, ReplaceAll
//  WinUtils::Dialog::      Message, Error, Warning, YesNo, YesNoCancel,
//                          OpenFile, SaveFile, BrowseFolder, InputBox
//  WinUtils::File::        Create, ReadAll, WriteAll, Append, Delete,
//                          Copy, Move, Exists, Size, CreateDir, DeleteDir,
//                          ListDir, ExeDir, TempDir, TempFile
//  WinUtils::Mouse::       GetPos, SetPos, MoveBy, Hide, Show,
//                          LeftClick, RightClick, DoubleClick, Scroll,
//                          ClickAt, SetCursorIcon, Confine, SmoothMove
//  WinUtils::Keyboard::    Press, KeyDown, KeyUp, TypeText, IsDown,
//                          Copy, Paste, Undo
//  WinUtils::Clipboard::   GetText, SetText, Clear
//  WinUtils::Process::     OpenURL, OpenFile, Run, RunCapture, Kill,
//                          CurrentPID, ListProcesses, IsRunning, Exit
//  WinUtils::Window::      FindByTitle, SetTitle, GetTitle, Show,
//                          Minimize, Maximize, Restore, BringToFront,
//                          SetBounds, GetConsole, SetAlwaysOnTop,
//                          SetOpacity, GetScreenSize, CenterOnScreen
//  WinUtils::System::      GetUsername, GetComputerName, GetWindowsVersion,
//                          GetMemoryMB, GetCPUCount, GetSpecialFolder,
//                          Desktop, AppData, Documents, Downloads, System32,
//                          Sleep, Now, SetEnv, GetEnv, LockScreen, Power
//  WinUtils::Registry::    ReadString, WriteString, DeleteValue,
//                          AddToStartup, RemoveFromStartup
//  WinUtils::Notify::      Balloon
//  WinUtils::Audio::       Beep, SystemSound, Tone, PlayWAV, StopSound
//  WinUtils::Log::         Logger, Default() .debug/.info/.warn/.error
//  WinUtils::Hotkey::      Register, UnregisterAll, Process, RunLoop
//  WinUtils::Screen::      Capture, GetPixelColor, GetPixelRGB
//
// ============================================================