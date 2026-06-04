/*
 * ============================================================================
 * wincore.hpp
 * Core aggregation header for the WinUtils project
 * ============================================================================
 *
 * WinUtils is a modular, header-only Windows utility framework providing
 * lightweight abstractions and helpers for native Win32 development.
 *
 * This header serves as the primary entry point for the full WinUtils library,
 * including system utilities, hardware access, security helpers, compatibility
 * layers, power management, mathematical utilities, and low-level Windows APIs.
 *
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
 * WARNING:
 *
 * This library interfaces directly with the Windows operating system and may
 * expose low-level functionality involving processes, memory, hardware, power
 * management, security descriptors, registry operations, and native APIs.
 *
 * Improper usage may result in instability, crashes, privilege escalation,
 * data corruption, or irreversible system modification.
 *
 * Use responsibly and only in environments where you understand the impact of
 * the operations being performed.
 *
 * ============================================================================
 *
 * Requires : Windows (Win32 API), C++17 or later
 * Includes : All WinUtils modules
 * Reference: See README.md for complete API documentation
 *
 * ============================================================================
*/

#pragma once

#include "wincompat.hpp"
#include "winutils.hpp"
#include "winmath.hpp"
#include "winaudio.hpp"
#include "winhardware.hpp"
#include "winpower.hpp"
#include "winsecurity.hpp"
#include "winkernel.hpp"
#include "winextra.hpp"