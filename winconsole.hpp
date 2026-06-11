/*
 * ============================================================================
 * WinConsole.hpp
 * Part of the WinUtils project — Console I/O, Formatting & Control
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
 * Requires : Windows (Win32 API), C++17 or later, WinUtils.hpp
 * Reference: See README.md for full namespace and function documentation
 *
 * ============================================================================
 *
 * Namespaces:
 *   WinUtils::Console::VT      — ANSI/VT escape code helpers
 *   WinUtils::Console          — Core console control & colored output
 *   WinUtils::Console::Cursor  — Cursor positioning & visibility
 *   WinUtils::Console::Input   — Raw/cooked input, password prompts
 *   WinUtils::Console::Draw    — Progress bars, spinners, tables, boxes
 *
 * ============================================================================
*/

#pragma once
#ifndef WIN_CONSOLE_HPP
#define WIN_CONSOLE_HPP

#include "WinUtils.hpp"

#include <io.h>
#include <fcntl.h>
#include <atomic>
#include <mutex>
#include <iostream>

#pragma comment(lib, "kernel32.lib")

namespace WinUtils {
namespace Console {

// ============================================================
//  Internal state
// ============================================================
namespace _Con {
    inline bool& _vtEnabled() { static bool v = false; return v; }
    inline HANDLE StdOut() { return GetStdHandle(STD_OUTPUT_HANDLE); }
    inline HANDLE StdIn()  { return GetStdHandle(STD_INPUT_HANDLE);  }
    inline HANDLE StdErr() { return GetStdHandle(STD_ERROR_HANDLE);  }

    // Mutex for thread-safe console output
    inline std::mutex& _mtx() { static std::mutex m; return m; }
}

// ============================================================
//  SECTION C1 — VT / ANSI Escape Sequences
// ============================================================
//  Virtual Terminal sequences give you colors, cursor control,
//  bold/italic/underline and more without needing to call
//  SetConsoleTextAttribute for every character.
//
//  Call Console::EnableVT() once at startup. If VT is not
//  supported (e.g. redirected output, old build of Windows 10),
//  the raw escape bytes are suppressed and the library falls
//  back to the legacy SetConsoleTextAttribute path.
// ============================================================
namespace VT {

    // ---- Standard foreground colors ----
    static constexpr const char* Black         = "\x1b[30m";
    static constexpr const char* Red           = "\x1b[31m";
    static constexpr const char* Green         = "\x1b[32m";
    static constexpr const char* Yellow        = "\x1b[33m";
    static constexpr const char* Blue          = "\x1b[34m";
    static constexpr const char* Magenta       = "\x1b[35m";
    static constexpr const char* Cyan          = "\x1b[36m";
    static constexpr const char* White         = "\x1b[37m";

    // ---- Bright foreground colors ----
    static constexpr const char* BrightBlack   = "\x1b[90m";
    static constexpr const char* BrightRed     = "\x1b[91m";
    static constexpr const char* BrightGreen   = "\x1b[92m";
    static constexpr const char* BrightYellow  = "\x1b[93m";
    static constexpr const char* BrightBlue    = "\x1b[94m";
    static constexpr const char* BrightMagenta = "\x1b[95m";
    static constexpr const char* BrightCyan    = "\x1b[96m";
    static constexpr const char* BrightWhite   = "\x1b[97m";

    // ---- Standard background colors ----
    static constexpr const char* BgBlack       = "\x1b[40m";
    static constexpr const char* BgRed         = "\x1b[41m";
    static constexpr const char* BgGreen       = "\x1b[42m";
    static constexpr const char* BgYellow      = "\x1b[43m";
    static constexpr const char* BgBlue        = "\x1b[44m";
    static constexpr const char* BgMagenta     = "\x1b[45m";
    static constexpr const char* BgCyan        = "\x1b[46m";
    static constexpr const char* BgWhite       = "\x1b[47m";

    // ---- Bright background colors ----
    static constexpr const char* BgBrightBlack   = "\x1b[100m";
    static constexpr const char* BgBrightRed     = "\x1b[101m";
    static constexpr const char* BgBrightGreen   = "\x1b[102m";
    static constexpr const char* BgBrightYellow  = "\x1b[103m";
    static constexpr const char* BgBrightBlue    = "\x1b[104m";
    static constexpr const char* BgBrightMagenta = "\x1b[105m";
    static constexpr const char* BgBrightCyan    = "\x1b[106m";
    static constexpr const char* BgBrightWhite   = "\x1b[107m";

    // ---- Text attributes ----
    static constexpr const char* Reset        = "\x1b[0m";
    static constexpr const char* Bold         = "\x1b[1m";
    static constexpr const char* Dim          = "\x1b[2m";
    static constexpr const char* Italic       = "\x1b[3m";
    static constexpr const char* Underline    = "\x1b[4m";
    static constexpr const char* Blink        = "\x1b[5m";
    static constexpr const char* Reverse      = "\x1b[7m";
    static constexpr const char* Strikethrough= "\x1b[9m";
    static constexpr const char* NoUnderline  = "\x1b[24m";
    static constexpr const char* NoBold       = "\x1b[22m";

    // ---- Cursor & screen ----
    static constexpr const char* ClearScreen  = "\x1b[2J\x1b[H";
    static constexpr const char* ClearLine    = "\x1b[2K\r";
    static constexpr const char* CursorHide   = "\x1b[?25l";
    static constexpr const char* CursorShow   = "\x1b[?25h";
    static constexpr const char* SaveCursor   = "\x1b[s";
    static constexpr const char* RestoreCursor= "\x1b[u";

    /// Build a 24-bit true-color foreground sequence: ESC[38;2;R;G;Bm
    inline std::string FgRGB(int r, int g, int b) {
        return "\x1b[38;2;" + std::to_string(r) + ";" +
                              std::to_string(g) + ";" +
                              std::to_string(b) + "m";
    }

    /// Build a 24-bit true-color background sequence: ESC[48;2;R;G;Bm
    inline std::string BgRGB(int r, int g, int b) {
        return "\x1b[48;2;" + std::to_string(r) + ";" +
                              std::to_string(g) + ";" +
                              std::to_string(b) + "m";
    }

    /// Move cursor to absolute position (1-based)
    inline std::string MoveTo(int row, int col) {
        return "\x1b[" + std::to_string(row) + ";" + std::to_string(col) + "H";
    }

    /// Move cursor up N rows
    inline std::string Up(int n = 1)    { return "\x1b[" + std::to_string(n) + "A"; }
    /// Move cursor down N rows
    inline std::string Down(int n = 1)  { return "\x1b[" + std::to_string(n) + "B"; }
    /// Move cursor right N columns
    inline std::string Right(int n = 1) { return "\x1b[" + std::to_string(n) + "C"; }
    /// Move cursor left N columns
    inline std::string Left(int n = 1)  { return "\x1b[" + std::to_string(n) + "D"; }

    /// Erase from cursor to end of line
    static constexpr const char* EraseToEndOfLine   = "\x1b[0K";
    /// Erase from start of line to cursor
    static constexpr const char* EraseFromLineStart = "\x1b[1K";

} // namespace VT

// ============================================================
//  SECTION C2 — Core Console Control
// ============================================================

/// Enable Virtual Terminal (ANSI escape) processing on stdout/stderr.
/// Call once at program startup. Returns true if VT is supported.
/// On older Windows 10 builds or when output is redirected, returns false
/// and the library falls back to SetConsoleTextAttribute automatically.
inline bool EnableVT() {
    DWORD mode = 0;
    HANDLE h = _Con::StdOut();
    if (!GetConsoleMode(h, &mode)) return false;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    bool ok = SetConsoleMode(h, mode) != FALSE;
    // Also enable on stderr
    HANDLE he = _Con::StdErr();
    DWORD em = 0;
    if (GetConsoleMode(he, &em))
        SetConsoleMode(he, em | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    _Con::_vtEnabled() = ok;
    return ok;
}

/// Check if VT mode is active
inline bool IsVTEnabled() { return _Con::_vtEnabled(); }

/// Check if stdout is attached to a real console (not redirected to a file/pipe)
inline bool IsConsole() {
    return _isatty(_fileno(stdout)) != 0;
}

/// Attach to an existing console or create a new one.
/// Useful for GUI apps that want a debug console window.
inline bool Attach() {
    if (AttachConsole(ATTACH_PARENT_PROCESS)) return true;
    return AllocConsole() != FALSE;
}

/// Detach and close the console window.
inline void Detach() {
    FreeConsole();
}

/// Set the console window title.
inline void SetTitle(const std::string& title) {
    SetConsoleTitleW(Str::ToWide(title).c_str());
}

/// Get the current console window title.
inline std::string GetTitle() {
    wchar_t buf[512] = {};
    GetConsoleTitleW(buf, 512);
    return Str::ToNarrow(buf);
}

/// Resize the console buffer and window.
/// bufferLines: number of lines in the scroll-back buffer (0 = match window)
inline void SetSize(int cols, int rows, int bufferLines = 0) {
    HANDLE h = _Con::StdOut();
    COORD bufSize{ static_cast<SHORT>(cols),
                   static_cast<SHORT>(bufferLines > 0 ? bufferLines : rows) };
    SetConsoleScreenBufferSize(h, bufSize);
    SMALL_RECT win{ 0, 0,
        static_cast<SHORT>(cols - 1),
        static_cast<SHORT>(rows - 1) };
    SetConsoleWindowInfo(h, TRUE, &win);
}

/// Get current console window dimensions. Returns {cols, rows}.
inline std::pair<int,int> GetSize() {
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (!GetConsoleScreenBufferInfo(_Con::StdOut(), &csbi))
        return { 80, 24 };
    int cols = csbi.srWindow.Right  - csbi.srWindow.Left + 1;
    int rows = csbi.srWindow.Bottom - csbi.srWindow.Top  + 1;
    return { cols, rows };
}

/// Clear the entire console screen and reset cursor to (0,0).
inline void Clear() {
    if (_Con::_vtEnabled()) {
        std::fputs(VT::ClearScreen, stdout);
        std::fflush(stdout);
        return;
    }
    HANDLE h = _Con::StdOut();
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    GetConsoleScreenBufferInfo(h, &csbi);
    DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    COORD home{ 0, 0 };
    DWORD written = 0;
    FillConsoleOutputCharacterW(h, L' ', cellCount, home, &written);
    FillConsoleOutputAttribute(h, csbi.wAttributes, cellCount, home, &written);
    SetConsoleCursorPosition(h, home);
}

/// Set the legacy console text color (always works, even without VT).
/// fgColor: one of the FOREGROUND_* defines from WinUtils.hpp
/// bgColor: one of the BACKGROUND_* defines (0 for black background)
inline void SetColor(WORD fgColor, WORD bgColor = 0) {
    SetConsoleTextAttribute(_Con::StdOut(), fgColor | bgColor);
}

/// Reset console colors to default white-on-black.
inline void ResetColor() {
    if (_Con::_vtEnabled()) {
        std::fputs(VT::Reset, stdout);
        std::fflush(stdout);
    } else {
        SetConsoleTextAttribute(_Con::StdOut(), FOREGROUND_WHITE);
    }
}

/// Print text in a specific VT color sequence.
/// Falls back to SetConsoleTextAttribute if VT is not enabled.
/// vtColor: a VT:: color constant e.g. VT::BrightGreen
/// legacyAttr: fallback FOREGROUND_* attribute e.g. FOREGROUND_BRIGHT_GREEN
inline void Print(const std::string& text,
                  const char* vtColor    = nullptr,
                  WORD        legacyAttr = FOREGROUND_WHITE) {
    std::lock_guard<std::mutex> lock(_Con::_mtx());
    if (_Con::_vtEnabled() && vtColor) {
        std::fputs(vtColor, stdout);
        std::fputs(text.c_str(), stdout);
        std::fputs(VT::Reset, stdout);
    } else {
        SetConsoleTextAttribute(_Con::StdOut(), legacyAttr);
        std::fputs(text.c_str(), stdout);
        SetConsoleTextAttribute(_Con::StdOut(), FOREGROUND_WHITE);
    }
    std::fflush(stdout);
}

/// Print text followed by a newline.
inline void PrintLine(const std::string& text,
                      const char* vtColor    = nullptr,
                      WORD        legacyAttr = FOREGROUND_WHITE) {
    Print(text + "\n", vtColor, legacyAttr);
}

// ---- Convenience wrappers for common log-style output ----

/// Print a success message in bright green.
inline void Success(const std::string& msg) {
    Print("[+] " + msg + "\n", VT::BrightGreen, FOREGROUND_BRIGHT_GREEN);
}

/// Print an info message in bright cyan.
inline void Info(const std::string& msg) {
    Print("[*] " + msg + "\n", VT::BrightCyan, FOREGROUND_CYAN | FOREGROUND_INTENSITY);
}

/// Print a warning message in bright yellow.
inline void Warn(const std::string& msg) {
    Print("[!] " + msg + "\n", VT::BrightYellow, FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
}

/// Print an error message in bright red.
inline void Error(const std::string& msg) {
    Print("[-] " + msg + "\n", VT::BrightRed, FOREGROUND_BRIGHT_RED);
}

/// Print a debug message in dim white (only in debug builds).
inline void Debug(const std::string& msg) {
#ifdef _DEBUG
    Print("[~] " + msg + "\n", VT::BrightBlack, FOREGROUND_WHITE);
#else
    (void)msg;
#endif
}

/// Print a bold/header line in bright white.
inline void Header(const std::string& msg) {
    if (_Con::_vtEnabled())
        Print(std::string(VT::Bold) + msg + "\n", VT::BrightWhite, FOREGROUND_BRIGHT_WHITE);
    else
        PrintLine(msg, nullptr, FOREGROUND_BRIGHT_WHITE);
}

/// Print a section separator line (full console width).
inline void Separator(char ch = '-', const char* vtColor = nullptr, WORD legacyAttr = FOREGROUND_WHITE) {
    auto [cols, rows] = GetSize();
    Print(std::string(cols, ch) + "\n", vtColor, legacyAttr);
}

// ============================================================
//  SECTION C3 — Cursor Control
// ============================================================
namespace Cursor {

    /// Move the cursor to a specific (col, row) position (0-based).
    inline void MoveTo(int col, int row) {
        if (_Con::_vtEnabled()) {
            // VT uses 1-based positions
            std::string seq = VT::MoveTo(row + 1, col + 1);
            std::fputs(seq.c_str(), stdout);
            std::fflush(stdout);
        } else {
            COORD c{ static_cast<SHORT>(col), static_cast<SHORT>(row) };
            SetConsoleCursorPosition(_Con::StdOut(), c);
        }
    }

    /// Get the current cursor position. Returns {col, row} (0-based).
    inline std::pair<int,int> GetPos() {
        CONSOLE_SCREEN_BUFFER_INFO csbi{};
        GetConsoleScreenBufferInfo(_Con::StdOut(), &csbi);
        return { csbi.dwCursorPosition.X, csbi.dwCursorPosition.Y };
    }

    /// Hide the cursor (useful during progress bar rendering).
    inline void Hide() {
        if (_Con::_vtEnabled()) {
            std::fputs(VT::CursorHide, stdout);
            std::fflush(stdout);
        } else {
            CONSOLE_CURSOR_INFO ci{};
            GetConsoleCursorInfo(_Con::StdOut(), &ci);
            ci.bVisible = FALSE;
            SetConsoleCursorInfo(_Con::StdOut(), &ci);
        }
    }

    /// Show the cursor again.
    inline void Show() {
        if (_Con::_vtEnabled()) {
            std::fputs(VT::CursorShow, stdout);
            std::fflush(stdout);
        } else {
            CONSOLE_CURSOR_INFO ci{};
            GetConsoleCursorInfo(_Con::StdOut(), &ci);
            ci.bVisible = TRUE;
            SetConsoleCursorInfo(_Con::StdOut(), &ci);
        }
    }

    /// Save the current cursor position.
    inline void Save() {
        if (_Con::_vtEnabled()) {
            std::fputs(VT::SaveCursor, stdout);
            std::fflush(stdout);
        }
    }

    /// Restore the previously saved cursor position.
    inline void Restore() {
        if (_Con::_vtEnabled()) {
            std::fputs(VT::RestoreCursor, stdout);
            std::fflush(stdout);
        }
    }

    /// Move the cursor up N rows from its current position.
    inline void MoveUp(int n = 1) {
        if (_Con::_vtEnabled()) {
            std::fputs(VT::Up(n).c_str(), stdout);
            std::fflush(stdout);
        } else {
            auto [col, row] = GetPos();
            MoveTo(col, std::max(0, row - n));
        }
    }

    /// Move the cursor down N rows.
    inline void MoveDown(int n = 1) {
        if (_Con::_vtEnabled()) {
            std::fputs(VT::Down(n).c_str(), stdout);
            std::fflush(stdout);
        } else {
            auto [col, row] = GetPos();
            MoveTo(col, row + n);
        }
    }

    /// Move the cursor to the start of the current line.
    inline void CarriageReturn() {
        std::fputc('\r', stdout);
        std::fflush(stdout);
    }

    /// Set the cursor size: 1-100 (percentage fill of the character cell).
    /// 1-25 = thin underline, 26-50 = medium, 51-100 = full block.
    inline void SetSize(int percent) {
        CONSOLE_CURSOR_INFO ci{};
        GetConsoleCursorInfo(_Con::StdOut(), &ci);
        ci.dwSize   = static_cast<DWORD>(std::clamp(percent, 1, 100));
        ci.bVisible = TRUE;
        SetConsoleCursorInfo(_Con::StdOut(), &ci);
    }

} // namespace Cursor

// ============================================================
//  SECTION C4 — Input Utilities
// ============================================================
namespace Input {

    /// Read a single keypress without echoing it or waiting for Enter.
    /// Returns the virtual key code.
    inline int ReadKey() {
        DWORD oldMode = 0;
        HANDLE h = _Con::StdIn();
        GetConsoleMode(h, &oldMode);
        SetConsoleMode(h, 0); // raw mode: no echo, no line buffering
        INPUT_RECORD rec{};
        DWORD count = 0;
        while (true) {
            ReadConsoleInputW(h, &rec, 1, &count);
            if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown)
                break;
        }
        SetConsoleMode(h, oldMode);
        return rec.Event.KeyEvent.wVirtualKeyCode;
    }

    /// Read a single character (not VK code) without echo.
    inline wchar_t ReadChar() {
        DWORD oldMode = 0;
        HANDLE h = _Con::StdIn();
        GetConsoleMode(h, &oldMode);
        SetConsoleMode(h, 0);
        INPUT_RECORD rec{};
        DWORD count = 0;
        while (true) {
            ReadConsoleInputW(h, &rec, 1, &count);
            if (rec.EventType == KEY_EVENT &&
                rec.Event.KeyEvent.bKeyDown &&
                rec.Event.KeyEvent.uChar.UnicodeChar != 0)
                break;
        }
        SetConsoleMode(h, oldMode);
        return rec.Event.KeyEvent.uChar.UnicodeChar;
    }

    /// Read a password from the console with masked input (shows '*' per character).
    /// Returns the entered password string. Handles Backspace correctly.
    inline std::string ReadPassword(const std::string& prompt = "Password: ") {
        std::fputs(prompt.c_str(), stdout);
        std::fflush(stdout);

        DWORD oldMode = 0;
        HANDLE h = _Con::StdIn();
        GetConsoleMode(h, &oldMode);
        // Disable echo but keep line processing enough for Ctrl+C
        SetConsoleMode(h, ENABLE_PROCESSED_INPUT);

        std::string password;
        while (true) {
            wchar_t ch = L'\0';
            DWORD read = 0;
            ReadConsoleW(h, &ch, 1, &read, nullptr);
            if (ch == L'\r' || ch == L'\n') {
                std::fputc('\n', stdout);
                break;
            }
            if (ch == L'\b' || ch == 127) { // backspace
                if (!password.empty()) {
                    password.pop_back();
                    std::fputs("\b \b", stdout);
                    std::fflush(stdout);
                }
                continue;
            }
            if (ch == 3) { // Ctrl+C
                SetConsoleMode(h, oldMode);
                password.clear();
                return {};
            }
            password += static_cast<char>(ch);
            std::fputc('*', stdout);
            std::fflush(stdout);
        }
        SetConsoleMode(h, oldMode);
        return password;
    }

    /// Prompt the user with a yes/no question. Returns true for 'y'/'Y'.
    /// Keeps asking until a valid answer is given.
    inline bool YesNo(const std::string& prompt) {
        while (true) {
            std::fputs((prompt + " [y/n]: ").c_str(), stdout);
            std::fflush(stdout);
            wchar_t ch = ReadChar();
            std::fputc('\n', stdout);
            if (ch == L'y' || ch == L'Y') return true;
            if (ch == L'n' || ch == L'N') return false;
            Warn("Please enter 'y' or 'n'.");
        }
    }

    /// Prompt the user for a line of text (normal echoed input).
    inline std::string ReadLine(const std::string& prompt = "") {
        if (!prompt.empty()) {
            std::fputs(prompt.c_str(), stdout);
            std::fflush(stdout);
        }
        std::string line;
        std::getline(std::cin, line);
        return line;
    }

    /// Wait for the user to press any key before continuing.
    inline void PressAnyKey(const std::string& msg = "Press any key to continue...") {
        std::fputs(msg.c_str(), stdout);
        std::fflush(stdout);
        ReadKey();
        std::fputc('\n', stdout);
    }

    /// Check if a key is currently held (non-blocking).
    inline bool IsKeyDown(int vk) {
        return (GetAsyncKeyState(vk) & 0x8000) != 0;
    }

    /// Flush the console input buffer (discard any queued keypresses).
    inline void FlushInput() {
        FlushConsoleInputBuffer(_Con::StdIn());
    }

} // namespace Input

// ============================================================
//  SECTION C5 — Draw Utilities (Progress, Spinners, Tables)
// ============================================================
namespace Draw {

    // ----------------------------------------------------------
    //  Progress Bar
    // ----------------------------------------------------------

    /// Style options for the progress bar.
    struct ProgressStyle {
        char        fill       = '#'; ///< Filled portion character
        char        empty      = '-'; ///< Empty portion character
        char        left       = '['; ///< Left bracket
        char        right      = ']'; ///< Right bracket
        int         width      = 40;  ///< Bar width in characters (not counting brackets)
        bool        showPct    = true;///< Show percentage number
        bool        showValue  = false;///< Show current/total values
        const char* vtFillColor  = nullptr; ///< VT color for filled portion (e.g. VT::BrightGreen)
        const char* vtEmptyColor = nullptr; ///< VT color for empty portion
        WORD        legacyFill  = FOREGROUND_BRIGHT_GREEN;
        WORD        legacyEmpty = FOREGROUND_WHITE;
    };

    /// Render a single progress bar in-place (overwrites the current line).
    /// value: current value, total: maximum value
    /// Call repeatedly to animate; call with value==total for final state.
    inline void ProgressBar(int value, int total, const std::string& label = "",
                             const ProgressStyle& style = {}) {
        if (total <= 0) total = 1;
        value = std::clamp(value, 0, total);
        float pct     = static_cast<float>(value) / static_cast<float>(total);
        int   filled  = static_cast<int>(pct * style.width);
        int   empty   = style.width - filled;

        // Build the bar string
        std::string bar;
        bar += style.left;
        bar += std::string(filled,  style.fill);
        bar += std::string(empty,   style.empty);
        bar += style.right;

        if (style.showPct)
            bar += Str::Format(" %3d%%", static_cast<int>(pct * 100.0f));
        if (style.showValue)
            bar += Str::Format(" (%d/%d)", value, total);
        if (!label.empty())
            bar = label + " " + bar;

        // Overwrite the current line
        std::lock_guard<std::mutex> lock(_Con::_mtx());
        std::fputc('\r', stdout);
        std::fputs(VT::EraseToEndOfLine, stdout);

        if (_Con::_vtEnabled()) {
            // Print label first (no color)
            if (!label.empty()) {
                std::fputs(label.c_str(), stdout);
                std::fputc(' ', stdout);
            }
            // Left bracket
            std::fputc(style.left, stdout);
            // Filled portion
            if (style.vtFillColor) std::fputs(style.vtFillColor, stdout);
            std::fputs(std::string(filled,  style.fill).c_str(), stdout);
            if (style.vtFillColor) std::fputs(VT::Reset, stdout);
            // Empty portion
            if (style.vtEmptyColor) std::fputs(style.vtEmptyColor, stdout);
            std::fputs(std::string(empty,   style.empty).c_str(), stdout);
            if (style.vtEmptyColor) std::fputs(VT::Reset, stdout);
            // Right bracket + suffix
            std::fputc(style.right, stdout);
            if (style.showPct)
                std::fputs(Str::Format(" %3d%%", static_cast<int>(pct * 100.0f)).c_str(), stdout);
            if (style.showValue)
                std::fputs(Str::Format(" (%d/%d)", value, total).c_str(), stdout);
        } else {
            std::fputs(bar.c_str(), stdout);
        }
        std::fflush(stdout);

        // Print newline when done
        if (value >= total) std::fputc('\n', stdout);
    }

    // ----------------------------------------------------------
    //  Spinner
    // ----------------------------------------------------------

    /// A simple in-place animated spinner for indeterminate progress.
    ///
    /// Usage:
    ///   Draw::Spinner sp("Loading...");
    ///   sp.Start();
    ///   // ... do work ...
    ///   sp.Stop("Done!");
    struct Spinner {
        std::string             label;
        std::vector<std::string> frames;
        DWORD                   intervalMs = 80;
        const char*             vtColor    = nullptr;
        WORD                    legacyAttr = FOREGROUND_CYAN | FOREGROUND_INTENSITY;

    private:
        std::atomic<bool>       _running{ false };
        std::thread             _thread;

    public:
        explicit Spinner(const std::string& label_ = "Working...",
                         const std::vector<std::string>& frames_ = { "|", "/", "-", "\\" },
                         DWORD intervalMs_ = 80)
            : label(label_), frames(frames_), intervalMs(intervalMs_) {}

        /// Start the spinner animation on a background thread.
        void Start() {
            _running = true;
            Cursor::Hide();
            _thread = std::thread([this]() {
                size_t i = 0;
                while (_running) {
                    {
                        std::lock_guard<std::mutex> lock(_Con::_mtx());
                        std::fputc('\r', stdout);
                        std::fputs(VT::EraseToEndOfLine, stdout);
                        if (_Con::_vtEnabled() && vtColor) std::fputs(vtColor, stdout);
                        std::fputs(frames[i % frames.size()].c_str(), stdout);
                        if (_Con::_vtEnabled() && vtColor) std::fputs(VT::Reset, stdout);
                        std::fputc(' ', stdout);
                        std::fputs(label.c_str(), stdout);
                        std::fflush(stdout);
                    }
                    ++i;
                    ::Sleep(intervalMs);
                }
            });
        }

        /// Stop the spinner and print an optional completion message.
        void Stop(const std::string& doneMsg = "") {
            _running = false;
            if (_thread.joinable()) _thread.join();
            std::lock_guard<std::mutex> lock(_Con::_mtx());
            std::fputc('\r', stdout);
            std::fputs(VT::EraseToEndOfLine, stdout);
            if (!doneMsg.empty()) {
                std::fputs(doneMsg.c_str(), stdout);
                std::fputc('\n', stdout);
            }
            std::fflush(stdout);
            Cursor::Show();
        }

        ~Spinner() {
            if (_running) Stop();
        }
    };

    // ---- Preset spinner styles ----
    inline Spinner MakeBrailleSpinner(const std::string& label = "Working...") {
        return Spinner(label, { "⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏" }, 80);
    }
    inline Spinner MakeDotSpinner(const std::string& label = "Working...") {
        return Spinner(label, { ".  ", ".. ", "..." }, 300);
    }
    inline Spinner MakeArrowSpinner(const std::string& label = "Working...") {
        return Spinner(label, { "→", "↘", "↓", "↙", "←", "↖", "↑", "↗" }, 100);
    }

    // ----------------------------------------------------------
    //  Box Drawing
    // ----------------------------------------------------------

    /// Box drawing character sets
    struct BoxStyle {
        const char* tl; ///< top-left corner
        const char* tr; ///< top-right corner
        const char* bl; ///< bottom-left corner
        const char* br; ///< bottom-right corner
        const char* h;  ///< horizontal line
        const char* v;  ///< vertical line
        const char* mt; ///< middle-top (T pointing down)
        const char* mb; ///< middle-bottom (T pointing up)
        const char* ml; ///< middle-left (T pointing right)
        const char* mr; ///< middle-right (T pointing left)
        const char* mc; ///< middle-center (cross)
    };

    // ┌─┐└─┘│─┬┴├┤┼
    static constexpr BoxStyle BoxSingle = {
        "┌","┐","└","┘","─","│","┬","┴","├","┤","┼"
    };
    // ╔═╗╚═╝║═╦╩╠╣╬
    static constexpr BoxStyle BoxDouble = {
        "╔","╗","╚","╝","═","║","╦","╩","╠","╣","╬"
    };
    // Simple ASCII box
    static constexpr BoxStyle BoxASCII = {
        "+","+","+","+","-","|","+","+","+","+","+"
    };
    // Rounded corners
    static constexpr BoxStyle BoxRounded = {
        "╭","╮","╰","╯","─","│","┬","┴","├","┤","┼"
    };

    /// Draw a simple titled box around a block of text.
    /// Returns the fully formatted string (does not print — caller decides).
    inline std::string Box(const std::string& content,
                           const std::string& title = "",
                           const BoxStyle& style    = BoxSingle,
                           int minWidth             = 0) {
        // Split content into lines
        auto lines = Str::Split(content, '\n');
        int innerW = minWidth;
        for (auto& l : lines)
            innerW = std::max(innerW, static_cast<int>(l.size()));
        if (!title.empty())
            innerW = std::max(innerW, static_cast<int>(title.size() + 2));

        std::string out;
        auto hLine = [&](int w) {
            std::string h;
            for (int i = 0; i < w; ++i) h += style.h;
            return h;
        };

        // Top border
        if (!title.empty()) {
            std::string titlePad = " " + title + " ";
            int rem = innerW - static_cast<int>(title.size() + 2);
            int lpad = rem / 2, rpad = rem - lpad;
            out += style.tl;
            for (int i = 0; i < lpad; ++i) out += style.h;
            out += titlePad;
            for (int i = 0; i < rpad; ++i) out += style.h;
            out += style.tr;
        } else {
            out += style.tl;
            out += hLine(innerW + 2);
            out += style.tr;
        }
        out += "\n";

        // Content lines
        for (auto& l : lines) {
            int pad = innerW - static_cast<int>(l.size());
            out += style.v;
            out += " ";
            out += l;
            out += std::string(pad, ' ');
            out += " ";
            out += style.v;
            out += "\n";
        }

        // Bottom border
        out += style.bl;
        out += hLine(innerW + 2);
        out += style.br;
        out += "\n";

        return out;
    }

    /// Print a box directly to stdout.
    inline void PrintBox(const std::string& content,
                         const std::string& title    = "",
                         const BoxStyle& style       = BoxSingle,
                         int minWidth                = 0,
                         const char* vtColor         = nullptr,
                         WORD        legacyAttr      = FOREGROUND_WHITE) {
        std::string b = Box(content, title, style, minWidth);
        Print(b, vtColor, legacyAttr);
    }

    // ----------------------------------------------------------
    //  Table
    // ----------------------------------------------------------

    /// Simple left-aligned table formatter.
    ///
    /// Usage:
    ///   Draw::Table t({"Name", "Version", "Status"});
    ///   t.AddRow({"WinUtils", "1.0.0", "Active"});
    ///   t.AddRow({"WinAudio", "1.0.0", "Active"});
    ///   t.Print();
    struct Table {
        std::vector<std::string>              headers;
        std::vector<std::vector<std::string>> rows;
        BoxStyle                              boxStyle = BoxSingle;
        const char*                           vtHeaderColor = VT::BrightWhite;
        WORD                                  legacyHeaderAttr = FOREGROUND_BRIGHT_WHITE;
        char                                  colSep = ' '; ///< padding character between columns

        explicit Table(const std::vector<std::string>& headers_)
            : headers(headers_) {}

        void AddRow(const std::vector<std::string>& row) {
            rows.push_back(row);
        }

        void Clear() { rows.clear(); }

        /// Render the table to a string.
        std::string Render() const {
            size_t cols = headers.size();
            std::vector<size_t> widths(cols, 0);

            // Compute column widths
            for (size_t c = 0; c < cols; ++c)
                widths[c] = headers[c].size();
            for (auto& row : rows)
                for (size_t c = 0; c < std::min(cols, row.size()); ++c)
                    widths[c] = std::max(widths[c], row[c].size());

            auto padRight = [](const std::string& s, size_t w) {
                return s + std::string(w - std::min(w, s.size()), ' ');
            };

            auto hSep = [&]() {
                std::string line = boxStyle.ml;
                for (size_t c = 0; c < cols; ++c) {
                    for (size_t i = 0; i < widths[c] + 2; ++i) line += boxStyle.h;
                    line += (c + 1 < cols) ? boxStyle.mc : boxStyle.mr;
                }
                return line + "\n";
            };

            auto topLine = [&]() {
                std::string line = boxStyle.tl;
                for (size_t c = 0; c < cols; ++c) {
                    for (size_t i = 0; i < widths[c] + 2; ++i) line += boxStyle.h;
                    line += (c + 1 < cols) ? boxStyle.mt : boxStyle.tr;
                }
                return line + "\n";
            };

            auto botLine = [&]() {
                std::string line = boxStyle.bl;
                for (size_t c = 0; c < cols; ++c) {
                    for (size_t i = 0; i < widths[c] + 2; ++i) line += boxStyle.h;
                    line += (c + 1 < cols) ? boxStyle.mb : boxStyle.br;
                }
                return line + "\n";
            };

            auto dataRow = [&](const std::vector<std::string>& row) {
                std::string line = boxStyle.v;
                for (size_t c = 0; c < cols; ++c) {
                    std::string cell = (c < row.size()) ? row[c] : "";
                    line += " " + padRight(cell, widths[c]) + " ";
                    line += boxStyle.v;
                }
                return line + "\n";
            };

            std::string out;
            out += topLine();
            out += dataRow(headers);
            out += hSep();
            for (auto& row : rows)
                out += dataRow(row);
            out += botLine();
            return out;
        }

        /// Print the table to stdout, with colored headers.
        void Print() const {
            // We print line-by-line so we can color just the header row
            size_t cols = headers.size();
            std::vector<size_t> widths(cols, 0);
            for (size_t c = 0; c < cols; ++c)
                widths[c] = headers[c].size();
            for (auto& row : rows)
                for (size_t c = 0; c < std::min(cols, row.size()); ++c)
                    widths[c] = std::max(widths[c], row[c].size());

            auto padRight = [](const std::string& s, size_t w) {
                return s + std::string(w - std::min(w, s.size()), ' ');
            };

            // Render full table as string, then print
            // Color the header row by finding its line
            std::string tbl = Render();
            auto lines = Str::Split(tbl, '\n');

            for (size_t i = 0; i < lines.size(); ++i) {
                if (i == 1) // header data row is always line index 1
                    PrintLine(lines[i], vtHeaderColor, legacyHeaderAttr);
                else if (!lines[i].empty())
                    PrintLine(lines[i]);
            }
        }
    };

    // ----------------------------------------------------------
    //  Misc helpers
    // ----------------------------------------------------------

    /// Print a simple key=value list, aligned.
    inline void KeyValueList(const std::vector<std::pair<std::string,std::string>>& items,
                             const char* keyColor = VT::BrightCyan,
                             WORD keyLegacy       = FOREGROUND_CYAN | FOREGROUND_INTENSITY) {
        size_t maxKey = 0;
        for (auto& [k, v] : items) maxKey = std::max(maxKey, k.size());
        for (auto& [k, v] : items) {
            Print(k + std::string(maxKey - k.size(), ' ') + " : ", keyColor, keyLegacy);
            PrintLine(v);
        }
    }

    /// Print a two-column status line e.g. "Service Name ......... [OK]"
    /// statusOk: true = show green [OK], false = show red [FAIL]
    inline void StatusLine(const std::string& label, bool statusOk,
                           int totalWidth = 60) {
        std::string dots(std::max(1, totalWidth - static_cast<int>(label.size()) - 7), '.');
        Print(label + " " + dots + " ");
        if (statusOk)
            PrintLine("[ OK ]", VT::BrightGreen, FOREGROUND_BRIGHT_GREEN);
        else
            PrintLine("[FAIL]", VT::BrightRed, FOREGROUND_BRIGHT_RED);
    }

    /// Print a centered text line within the current console width.
    inline void Centered(const std::string& text,
                         const char* vtColor = nullptr,
                         WORD legacyAttr     = FOREGROUND_WHITE) {
        auto [cols, rows] = GetSize();
        int pad = std::max(0, (cols - static_cast<int>(text.size())) / 2);
        PrintLine(std::string(pad, ' ') + text, vtColor, legacyAttr);
    }

    /// Print a horizontal rule with an optional centered label.
    /// e.g.:  ──────── Section Title ────────
    inline void Rule(const std::string& label = "",
                     char lineChar            = '-',
                     const char* vtColor      = nullptr,
                     WORD legacyAttr          = FOREGROUND_WHITE) {
        auto [cols, rows] = GetSize();
        if (label.empty()) {
            PrintLine(std::string(cols, lineChar), vtColor, legacyAttr);
            return;
        }
        int labelWidth = static_cast<int>(label.size()) + 2;
        int half = (cols - labelWidth) / 2;
        std::string line =
            std::string(half, lineChar) +
            " " + label + " " +
            std::string(cols - half - labelWidth, lineChar);
        PrintLine(line, vtColor, legacyAttr);
    }

} // namespace Draw

} // namespace Console
} // namespace WinUtils

#endif // WIN_CONSOLE_HPP