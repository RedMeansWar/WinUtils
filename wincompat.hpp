/*
 * ============================================================================
 * wincompat.hpp
 * Part of the WinUtils project — Compatibility & SDK Abstraction Layer
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
 * This header serves as a compatibility shim for non-MSVC toolchains (like
 * MinGW-w64) or older Windows SDK environments. It provides definitions for
 * newer Windows 10/11 API structures that may be missing from local headers.
 * ============================================================================
*/

#pragma once
#ifndef WINUTILS_COMPAT_HPP
#define WINUTILS_COMPAT_HPP

/*
============================================================================
Language Standard Enforcement
============================================================================
*/

#if __cplusplus < 201703L
#error "WinUtils requires C++17 or later."
#endif

/*
============================================================================
Windows Target Configuration
============================================================================
*/

// Windows 10 minimum target
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000002
#endif

/*
============================================================================
Windows Header Configuration
============================================================================
*/

// Prevent Windows macros from polluting STL
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Enable stricter Win32 type checking
#ifndef STRICT
#define STRICT
#endif

// Ensure full Win32 API exposure
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif

// Force Unicode APIs
#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

/*
============================================================================
Compiler Detection
============================================================================
*/

#if defined(_MSC_VER)
#define WINUTILS_COMPILER_MSVC
#elif defined(clang)
#define WINUTILS_COMPILER_CLANG
#elif defined(GNUC)
#define WINUTILS_COMPILER_GCC

#endif

/*
============================================================================
Architecture Detection
============================================================================
*/

#if defined(_M_X64) || defined(x86_64)
#define WINUTILS_ARCH_X64
#elif defined(_M_IX86) || defined(i386)
#define WINUTILS_ARCH_X86
#elif defined(_M_ARM64) || defined(aarch64)
#define WINUTILS_ARCH_ARM64
#endif

/*
============================================================================
Build Configuration & Symbol Export
============================================================================
*/

// DLL export/import support
#if defined(WINUTILS_BUILD_DLL)
#define WINUTILS_API __declspec(dllexport)
#elif defined(WINUTILS_USE_DLL)
#define WINUTILS_API __declspec(dllimport)
#else
#define WINUTILS_API
#endif

/*
============================================================================
Compiler Utility Macros
============================================================================
*/

// Force inline abstraction
#if defined(_MSC_VER)
#define WINUTILS_FORCEINLINE __forceinline
#else
#define WINUTILS_FORCEINLINE inline attribute((always_inline))
#endif

// noexcept abstraction
#define WINUTILS_NOEXCEPT noexcept

// constexpr abstraction
#define WINUTILS_CONSTEXPR constexpr

/*
============================================================================
Branch Prediction Hints
============================================================================
*/

#if defined(GNUC) || defined(clang)

#define WINUTILS_LIKELY(x) __builtin_expect(!!(x), 1)
#define WINUTILS_UNLIKELY(x) __builtin_expect(!!(x), 0)

#else

#define WINUTILS_LIKELY(x) (x)
#define WINUTILS_UNLIKELY(x) (x)

#endif

/*
============================================================================
Debug Configuration
============================================================================
*/

#if defined(_DEBUG) || !defined(NDEBUG)

#define WINUTILS_DEBUG

#endif

/*
============================================================================
Warning Control Helpers (MSVC)
============================================================================
*/

#if defined(_MSC_VER)
#define WINUTILS_WARNING_PUSH __pragma(warning(push))
#define WINUTILS_WARNING_POP __pragma(warning(pop))
#define WINUTILS_DISABLE_WARNING(x) __pragma(warning(disable : x))
#endif

/*
============================================================================
Library Version Information
============================================================================
*/

#define WINUTILS_VERSION_MAJOR 1
#define WINUTILS_VERSION_MINOR 0
#define WINUTILS_VERSION_PATCH 0

#define WINUTILS_VERSION "1.0.0"

/*
============================================================================
Windows API Includes
============================================================================
*/

#include <windows.h>

/*
============================================================================
SDK Compatibility Shims
============================================================================
*/

// Missing ProcessHeapPolicy definition
#ifndef ProcessHeapPolicy
#define ProcessHeapPolicy (PROCESS_MITIGATION_POLICY)6
#endif

// Missing PROCESS_MITIGATION_HEAP_POLICY structure
#ifndef PROCESS_MITIGATION_HEAP_POLICY

typedef struct _PROCESS_MITIGATION_HEAP_POLICY
{
union
{
DWORD dwFlags;

    struct
    {
        DWORD TerminateOnHeapCorruption : 1;
        DWORD ReservedFlags : 31;

    } DUMMYSTRUCTNAME;

} DUMMYUNIONNAME;

} PROCESS_MITIGATION_HEAP_POLICY,
*PPROCESS_MITIGATION_HEAP_POLICY;

#endif

/*
============================================================================
COM / WMI Compatibility
============================================================================
*/

#ifndef __uuidof
#define _uuidof(type) IID##type
#endif

#endif // WINUTILS_COMPAT_HPP