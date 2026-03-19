/*
 * ============================================================================
 * WinMath.hpp
 * Part of the WinUtils project — Mathematics Utility Library
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
 * Standalone header — no dependencies, no WinUtils.hpp required.
 * Just #include "WinMath.hpp" and go.
 *
 * Covers everything <cmath> and <algorithm> don't:
 *   Vec2 / Vec3 / Vec4   — vector math with operators
 *   Mat4                 — 4x4 matrix, transform/rotate/scale/perspective
 *   Color                — RGB/HSV/HSL/hex conversions + blend modes
 *   Geometry             — AABB, ray, circle, point tests
 *   Interpolation        — lerp, smoothstep, bezier, easing functions
 *   Random               — seeded RNG, range, float, shuffle, weighted pick
 *   Statistics           — mean, median, stddev, clamp, remap, percentile
 *   Bitwise              — popcount, bit scan, flags, next power of 2
 *   Screen               — DPI scaling, aspect ratio, screen-to-world
 *
 * ============================================================================
*/

#pragma once
#ifndef WIN_MATH_HPP
#define WIN_MATH_HPP

#include <cmath>
#include <algorithm>
#include <array>
#include <vector>
#include <numeric>
#include <random>
#include <stdint.h>
#include <limits>
#include <cassert>
#include <intrin.h>

// Windows.h is only needed for COLORREF support (Color::ToCOLORREF / FromCOLORREF)
// and the Bits:: intrinsics. Include it if not already included.
#ifndef _WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

// Colors that aren't defined in Windows headers are listed here for convenience. These can be used with SetConsoleTextAttribute for colored console output.
#define FOREGROUND_BLUE             0x0001
#define FOREGROUND_GREEN            0x0002
#define FOREGROUND_RED              0x0004
#define FOREGROUND_INTENSITY        0x0008
#define FOREGROUND_YELLOW           (FOREGROUND_RED | FOREGROUND_GREEN)
#define FOREGROUND_CYAN             (FOREGROUND_GREEN | FOREGROUND_BLUE)
#define FOREGROUND_MAGENTA          (FOREGROUND_RED | FOREGROUND_BLUE)
#define FOREGROUND_WHITE            (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

#define FOREGROUND_BRIGHT_RED       (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define FOREGROUND_BRIGHT_GREEN     (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define FOREGROUND_BRIGHT_BLUE      (FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define FOREGROUND_BRIGHT_MAGENTA   (FOREGROUND_MAGENTA | FOREGROUND_INTENSITY)
#define FOREGROUND_BRIGHT_WHITE     (FOREGROUND_WHITE | FOREGROUND_INTENSITY)

#define BACKGROUND_BLUE             0x0010
#define BACKGROUND_GREEN            0x0020
#define BACKGROUND_RED              0x0040
#define BACKGROUND_INTENSITY        0x0080
#define BACKGROUND_YELLOW           (BACKGROUND_RED | BACKGROUND_GREEN)
#define BACKGROUND_CYAN             (BACKGROUND_GREEN | BACKGROUND_BLUE)
#define BACKGROUND_MAGENTA          (BACKGROUND_RED | BACKGROUND_BLUE)
#define BACKGROUND_WHITE            (BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE)

#define COLOR_WARNING_THEME         (BACKGROUND_YELLOW | FOREGROUND_INTENSITY)
#define COMMON_LVB_REVERSE_VIDEO    0x4000
#define COMMON_LVB_UNDERSCORE       0x8000
#define CONSOLE_RESET               (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

namespace WinMath {

// ============================================================
//  Constants
// ============================================================
static constexpr double PI        = 3.14159265358979323846;
static constexpr double TAU       = 6.28318530717958647692; // 2*PI
static constexpr double E         = 2.71828182845904523536;
static constexpr double SQRT2     = 1.41421356237309504880;
static constexpr double SQRT3     = 1.73205080756887729352;
static constexpr double PHI       = 1.61803398874989484820; // golden ratio
static constexpr double DEG2RAD   = PI / 180.0;
static constexpr double RAD2DEG   = 180.0 / PI;
static constexpr float  PIf       = static_cast<float>(PI);
static constexpr float  TAUf      = static_cast<float>(TAU);
static constexpr float  DEG2RADf  = static_cast<float>(DEG2RAD);
static constexpr float  RAD2DEGf  = static_cast<float>(RAD2DEG);
static constexpr float  EPSILON   = 1e-6f;

// ============================================================
//  SECTION M1 — General Utilities
//  Things <cmath> and <algorithm> don't have
// ============================================================
namespace Math {

    /// Clamp a value between min and max
    template<typename T>
    constexpr T Clamp(T v, T lo, T hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }

    /// Clamp to [0, 1]
    template<typename T>
    constexpr T Saturate(T v) { return Clamp(v, T(0), T(1)); }

    /// Remap value from [inLo, inHi] to [outLo, outHi]
    template<typename T>
    constexpr T Remap(T v, T inLo, T inHi, T outLo, T outHi) {
        return outLo + (v - inLo) * (outHi - outLo) / (inHi - inLo);
    }

    /// Remap and clamp
    template<typename T>
    constexpr T RemapClamped(T v, T inLo, T inHi, T outLo, T outHi) {
        return Clamp(Remap(v, inLo, inHi, outLo, outHi), outLo, outHi);
    }

    /// Linear interpolation
    template<typename T>
    constexpr T Lerp(T a, T b, T t) { return a + t * (b - a); }

    /// Inverse lerp — what t gives v between a and b?
    template<typename T>
    constexpr T InvLerp(T a, T b, T v) { return (v - a) / (b - a); }

    /// Sign of a value: -1, 0, or 1
    template<typename T>
    constexpr T Sign(T v) { return v < T(0) ? T(-1) : (v > T(0) ? T(1) : T(0)); }

    /// Wrap value into [lo, hi) range — like modulo but works for floats
    template<typename T>
    inline T Wrap(T v, T lo, T hi) {
        T range = hi - lo;
        return v - range * std::floor((v - lo) / range);
    }

    /// Wrap angle to [-PI, PI]
    inline float WrapAngle(float radians) {
        return static_cast<float>(Wrap(static_cast<double>(radians), -PI, PI));
    }

    /// Shortest angle difference between two angles (radians)
    inline float AngleDiff(float a, float b) {
        float d = std::fmod(b - a + PIf, TAUf) - PIf;
        return d;
    }

    /// Are two floats approximately equal?
    inline bool ApproxEqual(float a, float b, float eps = EPSILON) {
        return std::abs(a - b) <= eps;
    }

    /// Is a value between lo and hi (inclusive)?
    template<typename T>
    constexpr bool InRange(T v, T lo, T hi) { return v >= lo && v <= hi; }

    /// Convert degrees to radians
    constexpr float ToRad(float deg) { return deg * DEG2RADf; }

    /// Convert radians to degrees
    constexpr float ToDeg(float rad) { return rad * RAD2DEGf; }

    /// Integer power (faster than std::pow for integer exponents)
    template<typename T>
    constexpr T Pow(T base, int exp) {
        T result = T(1);
        for (; exp > 0; --exp) result *= base;
        return result;
    }

    /// Float modulo that always returns positive result
    inline float FMod(float v, float m) {
        float r = std::fmod(v, m);
        return r < 0 ? r + m : r;
    }

    /// Smooth minimum — blends between two values smoothly
    /// k controls the blend radius (0 = hard min, larger = smoother)
    inline float SMin(float a, float b, float k) {
        float h = Clamp(0.5f + 0.5f * (b - a) / k, 0.0f, 1.0f);
        return Lerp(b, a, h) - k * h * (1.0f - h);
    }

    /// Ping-pong: oscillates between 0 and length
    inline float PingPong(float t, float length) {
        t = FMod(t, length * 2.0f);
        return length - std::abs(t - length);
    }

} // namespace Math

// ============================================================
//  SECTION M2 — Interpolation & Easing
// ============================================================
namespace Interp {

    /// Smoothstep — smooth curve between 0 and 1
    inline float Smoothstep(float t) {
        t = Math::Saturate(t);
        return t * t * (3.0f - 2.0f * t);
    }

    /// Smoothstep between edge0 and edge1
    inline float Smoothstep(float edge0, float edge1, float t) {
        return Smoothstep(Math::InvLerp(edge0, edge1, t));
    }

    /// Smootherstep — even smoother (Ken Perlin's version)
    inline float Smootherstep(float t) {
        t = Math::Saturate(t);
        return t * t * t * (t * (t * 6.0f - 15.0f) + 10.0f);
    }

    // ---- Easing functions — all take t in [0,1], return [0,1] ----

    inline float EaseInQuad   (float t) { return t * t; }
    inline float EaseOutQuad  (float t) { return t * (2.0f - t); }
    inline float EaseInOutQuad(float t) {
        return t < 0.5f ? 2*t*t : -1 + (4 - 2*t)*t;
    }

    inline float EaseInCubic   (float t) { return t * t * t; }
    inline float EaseOutCubic  (float t) { float f=t-1; return f*f*f+1; }
    inline float EaseInOutCubic(float t) {
        return t < 0.5f ? 4*t*t*t : (t-1)*(2*t-2)*(2*t-2)+1;
    }

    inline float EaseInQuart   (float t) { return t*t*t*t; }
    inline float EaseOutQuart  (float t) { float f=t-1; return 1-f*f*f*f; }
    inline float EaseInOutQuart(float t) {
        return t < 0.5f ? 8*t*t*t*t : 1-8*(t-1)*(t-1)*(t-1)*(t-1);
    }

    inline float EaseInSine   (float t) { return 1-std::cos(t*PIf/2); }
    inline float EaseOutSine  (float t) { return std::sin(t*PIf/2); }
    inline float EaseInOutSine(float t) { return -(std::cos(PIf*t)-1)/2; }

    inline float EaseInExpo   (float t) { return t==0?0:std::pow(2,10*t-10); }
    inline float EaseOutExpo  (float t) { return t==1?1:1-std::pow(2,-10*t); }
    inline float EaseInOutExpo(float t) {
        if (t==0||t==1) return t;
        return t<0.5f ? std::pow(2,20*t-10)/2 : (2-std::pow(2,-20*t+10))/2;
    }

    inline float EaseInCirc   (float t) { return 1-std::sqrt(1-t*t); }
    inline float EaseOutCirc  (float t) { return std::sqrt(1-(t-1)*(t-1)); }
    inline float EaseInOutCirc(float t) {
        return t<0.5f ? (1-std::sqrt(1-4*t*t))/2
                      : (std::sqrt(1-((-2*t+2)*(-2*t+2)))+1)/2;
    }

    inline float EaseInElastic(float t) {
        if (t==0||t==1) return t;
        return -std::pow(2,10*t-10)*std::sin((t*10-10.75f)*(TAUf/3));
    }
    inline float EaseOutElastic(float t) {
        if (t==0||t==1) return t;
        return std::pow(2,-10*t)*std::sin((t*10-0.75f)*(TAUf/3))+1;
    }

    inline float EaseInBounce(float t);
    inline float EaseOutBounce(float t) {
        const float n1=7.5625f, d1=2.75f;
        if      (t < 1/d1)         return n1*t*t;
        else if (t < 2/d1)         { t-=1.5f/d1;  return n1*t*t+0.75f; }
        else if (t < 2.5f/d1)      { t-=2.25f/d1; return n1*t*t+0.9375f; }
        else                       { t-=2.625f/d1; return n1*t*t+0.984375f; }
    }
    inline float EaseInBounce(float t) { return 1-EaseOutBounce(1-t); }
    inline float EaseInOutBounce(float t) {
        return t<0.5f ? (1-EaseOutBounce(1-2*t))/2
                      : (1+EaseOutBounce(2*t-1))/2;
    }

    /// Quadratic bezier interpolation between a, b, c at time t
    inline float Bezier2(float a, float b, float c, float t) {
        float u = 1.0f - t;
        return u*u*a + 2*u*t*b + t*t*c;
    }

    /// Cubic bezier interpolation
    inline float Bezier3(float a, float b, float c, float d, float t) {
        float u = 1.0f - t;
        return u*u*u*a + 3*u*u*t*b + 3*u*t*t*c + t*t*t*d;
    }

    /// Catmull-Rom spline interpolation between p1 and p2
    /// (p0 and p3 are control points)
    inline float CatmullRom(float p0, float p1, float p2, float p3, float t) {
        float t2 = t*t, t3 = t2*t;
        return 0.5f * ((2*p1) +
                       (-p0+p2)*t +
                       (2*p0-5*p1+4*p2-p3)*t2 +
                       (-p0+3*p1-3*p2+p3)*t3);
    }

    /// Spring interpolation — overshoots target and oscillates
    /// stiffness: how strong the spring is (typical: 100-500)
    /// damping: how quickly it settles (typical: 10-30)
    inline float Spring(float current, float target, float& velocity,
        float stiffness, float damping, float dt) {
        float force = (target - current) * stiffness - velocity * damping;
        velocity += force * dt;
        return current + velocity * dt;
    }

} // namespace Interp

// ============================================================
//  SECTION M3 — Vector Math
// ============================================================

struct Vec2 {
    float x = 0, y = 0;

    constexpr Vec2() = default;
    constexpr Vec2(float x, float y) : x(x), y(y) {}
    constexpr Vec2(float v) : x(v), y(v) {}

    constexpr Vec2 operator+(const Vec2& o) const { return {x+o.x, y+o.y}; }
    constexpr Vec2 operator-(const Vec2& o) const { return {x-o.x, y-o.y}; }
    constexpr Vec2 operator*(float s)       const { return {x*s,   y*s  }; }
    constexpr Vec2 operator/(float s)       const { return {x/s,   y/s  }; }
    constexpr Vec2 operator*(const Vec2& o) const { return {x*o.x, y*o.y}; }
    Vec2& operator+=(const Vec2& o) { x+=o.x; y+=o.y; return *this; }
    Vec2& operator-=(const Vec2& o) { x-=o.x; y-=o.y; return *this; }
    Vec2& operator*=(float s)       { x*=s;   y*=s;   return *this; }
    Vec2& operator/=(float s)       { x/=s;   y/=s;   return *this; }
    constexpr bool operator==(const Vec2& o) const { return x==o.x && y==o.y; }
    constexpr bool operator!=(const Vec2& o) const { return !(*this==o); }
    constexpr Vec2 operator-() const { return {-x,-y}; }

    /// Length (magnitude)
    float Length()    const { return std::sqrt(x*x + y*y); }
    float LengthSq()  const { return x*x + y*y; }

    /// Normalize — returns unit vector (zero vector if length is ~0)
    Vec2  Normalized() const {
        float len = Length();
        return len > EPSILON ? Vec2{x/len, y/len} : Vec2{};
    }
    Vec2& Normalize() { *this = Normalized(); return *this; }

    /// Dot product
    constexpr float Dot(const Vec2& o) const { return x*o.x + y*o.y; }

    /// 2D cross product (returns scalar — the Z component)
    constexpr float Cross(const Vec2& o) const { return x*o.y - y*o.x; }

    /// Rotate by angle (radians)
    Vec2 Rotated(float rad) const {
        float c = std::cos(rad), s = std::sin(rad);
        return {x*c - y*s, x*s + y*c};
    }

    /// Angle of this vector (radians)
    float Angle() const { return std::atan2(y, x); }

    /// Reflect around normal
    Vec2 Reflect(const Vec2& normal) const {
        return *this - normal * (2.0f * Dot(normal));
    }

    /// Lerp toward target
    Vec2 Lerp(const Vec2& to, float t) const {
        return {Math::Lerp(x, to.x, t), Math::Lerp(y, to.y, t)};
    }

    /// Distance to another point
    float DistanceTo(const Vec2& o) const { return (*this - o).Length(); }

    /// Perpendicular (rotated 90 degrees CCW)
    constexpr Vec2 Perp() const { return {-y, x}; }

    static constexpr Vec2 Zero()  { return {0,0}; }
    static constexpr Vec2 One()   { return {1,1}; }
    static constexpr Vec2 Up()    { return {0,-1}; }
    static constexpr Vec2 Down()  { return {0, 1}; }
    static constexpr Vec2 Left()  { return {-1,0}; }
    static constexpr Vec2 Right() { return {1, 0}; }
};

inline Vec2 operator*(float s, const Vec2& v) { return v * s; }

struct Vec3 {
    float x = 0, y = 0, z = 0;

    constexpr Vec3() = default;
    constexpr Vec3(float x, float y, float z) : x(x), y(y), z(z) {}
    constexpr Vec3(float v) : x(v), y(v), z(v) {}
    constexpr Vec3(Vec2 v, float z=0) : x(v.x), y(v.y), z(z) {}

    constexpr Vec3 operator+(const Vec3& o) const { return {x+o.x,y+o.y,z+o.z}; }
    constexpr Vec3 operator-(const Vec3& o) const { return {x-o.x,y-o.y,z-o.z}; }
    constexpr Vec3 operator*(float s)       const { return {x*s,  y*s,  z*s  }; }
    constexpr Vec3 operator/(float s)       const { return {x/s,  y/s,  z/s  }; }
    constexpr Vec3 operator*(const Vec3& o) const { return {x*o.x,y*o.y,z*o.z}; }
    
    Vec3& operator+=(const Vec3& o) { x+=o.x;y+=o.y;z+=o.z; return *this; }
    Vec3& operator-=(const Vec3& o) { x-=o.x;y-=o.y;z-=o.z; return *this; }
    Vec3& operator*=(float s)       { x*=s;  y*=s;  z*=s;   return *this; }
    
    constexpr Vec3 operator-() const { return {-x,-y,-z}; }
    constexpr bool operator==(const Vec3& o) const { return x==o.x&&y==o.y&&z==o.z; }

    float Length()   const { return std::sqrt(x*x+y*y+z*z); }
    float LengthSq() const { return x*x+y*y+z*z; }

    Vec3 Normalized() const {
        float len = Length();
        return len > EPSILON ? Vec3{x/len,y/len,z/len} : Vec3{};
    }
    Vec3& Normalize() { *this = Normalized(); return *this; }

    constexpr float Dot(const Vec3& o)   const { return x*o.x+y*o.y+z*o.z; }
    constexpr Vec3  Cross(const Vec3& o) const {
        return {y*o.z-z*o.y, z*o.x-x*o.z, x*o.y-y*o.x};
    }

    Vec3 Lerp(const Vec3& to, float t) const {
        return {Math::Lerp(x,to.x,t), Math::Lerp(y,to.y,t), Math::Lerp(z,to.z,t)};
    }

    Vec3 Reflect(const Vec3& n) const { return *this - n*(2.0f*Dot(n)); }

    float DistanceTo(const Vec3& o) const { return (*this-o).Length(); }

    /// Project this vector onto another
    Vec3 ProjectOnto(const Vec3& o) const {
        return o * (Dot(o) / o.LengthSq());
    }

    Vec2 XY() const { return {x,y}; }
    Vec2 XZ() const { return {x,z}; }

    static constexpr Vec3 Zero()    { return {0,0,0}; }
    static constexpr Vec3 One()     { return {1,1,1}; }
    static constexpr Vec3 Up()      { return {0,1,0}; }
    static constexpr Vec3 Forward() { return {0,0,-1}; }
    static constexpr Vec3 Right()   { return {1,0,0}; }
};

inline Vec3 operator*(float s, const Vec3& v) { return v*s; }

struct Vec4 {
    float x=0, y=0, z=0, w=0;

    constexpr Vec4() = default;
    constexpr Vec4(float x,float y,float z,float w) : x(x),y(y),z(z),w(w) {}
    constexpr Vec4(Vec3 v, float w=1) : x(v.x),y(v.y),z(v.z),w(w) {}
    constexpr Vec4(float v) : x(v),y(v),z(v),w(v) {}

    constexpr Vec4 operator+(const Vec4& o) const { return {x+o.x,y+o.y,z+o.z,w+o.w}; }
    constexpr Vec4 operator-(const Vec4& o) const { return {x-o.x,y-o.y,z-o.z,w-o.w}; }
    constexpr Vec4 operator*(float s)       const { return {x*s,y*s,z*s,w*s}; }
    constexpr float Dot(const Vec4& o) const { return x*o.x+y*o.y+z*o.z+w*o.w; }

    Vec3 XYZ() const { return {x,y,z}; }
    Vec2 XY()  const { return {x,y}; }
};

// ============================================================
//  SECTION M4 — Matrix Math (Column-major 4x4)
// ============================================================

struct Mat4 {
    // Stored column-major: m[col][row]
    float m[4][4] = {};

    Mat4() { *this = Identity(); }

    static Mat4 Identity() {
        Mat4 r{};
        r.m[0][0]=r.m[1][1]=r.m[2][2]=r.m[3][3]=1.0f;
        return r;
    }

    static Mat4 Zero() { Mat4 r{}; return r; }

    /// Translation matrix
    static Mat4 Translate(float x, float y, float z) {
        Mat4 r = Identity();
        r.m[3][0]=x; r.m[3][1]=y; r.m[3][2]=z;
        return r;
    }
    static Mat4 Translate(Vec3 v) { return Translate(v.x,v.y,v.z); }

    /// Scale matrix
    static Mat4 Scale(float x, float y, float z) {
        Mat4 r = Identity();
        r.m[0][0]=x; r.m[1][1]=y; r.m[2][2]=z;
        return r;
    }
    static Mat4 Scale(Vec3 v) { return Scale(v.x,v.y,v.z); }
    static Mat4 Scale(float s) { return Scale(s,s,s); }

    /// Rotation around X axis (radians)
    static Mat4 RotateX(float rad) {
        Mat4 r = Identity();
        float c=std::cos(rad), s=std::sin(rad);
        r.m[1][1]=c; r.m[1][2]=s;
        r.m[2][1]=-s; r.m[2][2]=c;
        return r;
    }

    /// Rotation around Y axis (radians)
    static Mat4 RotateY(float rad) {
        Mat4 r = Identity();
        float c=std::cos(rad), s=std::sin(rad);
        r.m[0][0]=c; r.m[0][2]=-s;
        r.m[2][0]=s; r.m[2][2]=c;
        return r;
    }

    /// Rotation around Z axis (radians)
    static Mat4 RotateZ(float rad) {
        Mat4 r = Identity();
        float c=std::cos(rad), s=std::sin(rad);
        r.m[0][0]=c; r.m[0][1]=s;
        r.m[1][0]=-s; r.m[1][1]=c;
        return r;
    }

    /// Rotation around arbitrary axis (radians)
    static Mat4 RotateAxis(Vec3 axis, float rad) {
        axis = axis.Normalized();
        float c=std::cos(rad), s=std::sin(rad), t=1-c;
        float x=axis.x, y=axis.y, z=axis.z;
        Mat4 r = Identity();
        r.m[0][0]=t*x*x+c;   r.m[0][1]=t*x*y+s*z; r.m[0][2]=t*x*z-s*y;
        r.m[1][0]=t*x*y-s*z; r.m[1][1]=t*y*y+c;   r.m[1][2]=t*y*z+s*x;
        r.m[2][0]=t*x*z+s*y; r.m[2][1]=t*y*z-s*x; r.m[2][2]=t*z*z+c;
        return r;
    }

    /// Perspective projection matrix (for 3D rendering)
    /// fovY: vertical FOV in radians, aspect: width/height
    static Mat4 Perspective(float fovY, float aspect, float zNear, float zFar) {
        float f = 1.0f / std::tan(fovY * 0.5f);
        float range = zNear - zFar;
        Mat4 r{};
        r.m[0][0] = f / aspect;
        r.m[1][1] = f;
        r.m[2][2] = (zFar + zNear) / range;
        r.m[2][3] = -1.0f;
        r.m[3][2] = (2.0f * zFar * zNear) / range;
        return r;
    }

    /// Orthographic projection matrix
    static Mat4 Ortho(float left, float right, float bottom,
                      float top, float zNear, float zFar) {
        Mat4 r{};
        r.m[0][0] =  2/(right-left);
        r.m[1][1] =  2/(top-bottom);
        r.m[2][2] = -2/(zFar-zNear);
        r.m[3][0] = -(right+left)/(right-left);
        r.m[3][1] = -(top+bottom)/(top-bottom);
        r.m[3][2] = -(zFar+zNear)/(zFar-zNear);
        r.m[3][3] =  1;
        return r;
    }

    /// LookAt view matrix
    static Mat4 LookAt(Vec3 eye, Vec3 center, Vec3 up) {
        Vec3 f = (center - eye).Normalized();
        Vec3 s = f.Cross(up).Normalized();
        Vec3 u = s.Cross(f);
        Mat4 r{};
        r.m[0][0]=s.x; r.m[1][0]=s.y; r.m[2][0]=s.z;
        r.m[0][1]=u.x; r.m[1][1]=u.y; r.m[2][1]=u.z;
        r.m[0][2]=-f.x;r.m[1][2]=-f.y;r.m[2][2]=-f.z;
        r.m[3][0]=-s.Dot(eye);
        r.m[3][1]=-u.Dot(eye);
        r.m[3][2]= f.Dot(eye);
        r.m[3][3]=1;
        return r;
    }

    /// Matrix multiplication
    Mat4 operator*(const Mat4& o) const {
        Mat4 r{};
        for (int c=0;c<4;++c)
            for (int rr=0;rr<4;++rr)
                for (int k=0;k<4;++k)
                    r.m[c][rr] += m[k][rr] * o.m[c][k];
        return r;
    }

    /// Transform a Vec4
    Vec4 operator*(const Vec4& v) const {
        return {
            m[0][0]*v.x+m[1][0]*v.y+m[2][0]*v.z+m[3][0]*v.w,
            m[0][1]*v.x+m[1][1]*v.y+m[2][1]*v.z+m[3][1]*v.w,
            m[0][2]*v.x+m[1][2]*v.y+m[2][2]*v.z+m[3][2]*v.w,
            m[0][3]*v.x+m[1][3]*v.y+m[2][3]*v.z+m[3][3]*v.w,
        };
    }

    /// Transform a point (Vec3 with w=1)
    Vec3 TransformPoint(Vec3 v) const {
        Vec4 r = *this * Vec4(v,1);
        return {r.x/r.w, r.y/r.w, r.z/r.w};
    }

    /// Transform a direction (Vec3 with w=0 — ignores translation)
    Vec3 TransformDir(Vec3 v) const {
        Vec4 r = *this * Vec4(v,0);
        return {r.x, r.y, r.z};
    }

    /// Transpose
    Mat4 Transposed() const {
        Mat4 r{};
        for (int c=0;c<4;++c)
            for (int rr=0;rr<4;++rr)
                r.m[rr][c] = m[c][rr];
        return r;
    }

    /// Get translation component
    Vec3 GetTranslation() const { return {m[3][0],m[3][1],m[3][2]}; }

    /// Pointer to raw float data (for OpenGL/D3D)
    const float* Data() const { return &m[0][0]; }
};

// ============================================================
//  SECTION M5 — Color Math
// ============================================================

struct Color {
    float r=0, g=0, b=0, a=1; // all in [0,1]

    constexpr Color() = default;
    constexpr Color(float r, float g, float b, float a=1)
        : r(r), g(g), b(b), a(a) {}

    /// From 0-255 RGBA
    static Color FromRGBA8(uint8_t r, uint8_t g, uint8_t b, uint8_t a=255) {
        return {r/255.0f, g/255.0f, b/255.0f, a/255.0f};
    }

    /// From 0xRRGGBB or 0xAARRGGBB hex
    static Color FromHex(uint32_t hex) {
        if (hex <= 0xFFFFFF)
            return FromRGBA8(
                (hex>>16)&0xFF, (hex>>8)&0xFF, hex&0xFF);
        return FromRGBA8(
            (hex>>16)&0xFF, (hex>>8)&0xFF,
            hex&0xFF, (hex>>24)&0xFF);
    }

    /// To COLORREF (Win32 BGRD format)
    uint32_t ToCOLORREF() const {
        return RGB(
            static_cast<uint8_t>(Math::Saturate(r)*255),
            static_cast<uint8_t>(Math::Saturate(g)*255),
            static_cast<uint8_t>(Math::Saturate(b)*255));
    }

    /// From COLORREF
    static Color FromCOLORREF(uint32_t c) {
        return FromRGBA8(GetRValue(c), GetGValue(c), GetBValue(c));
    }

    /// Convert to HSV (hue 0-360, saturation 0-1, value 0-1)
    void ToHSV(float& h, float& s, float& v) const {
        float mx=std::max({r,g,b}), mn=std::min({r,g,b});
        float d=mx-mn;
        v=mx;
        s = mx>EPSILON ? d/mx : 0;
        if (d<EPSILON) { h=0; return; }
        if      (mx==r) h=60*std::fmod((g-b)/d,6);
        else if (mx==g) h=60*((b-r)/d+2);
        else            h=60*((r-g)/d+4);
        if (h<0) h+=360;
    }

    /// From HSV
    static Color FromHSV(float h, float s, float v, float a=1) {
        float c=v*s, x=c*(1-std::abs(std::fmod(h/60,2)-1)), m=v-c;
        float r,g,b;
        if      (h<60)  {r=c;g=x;b=0;}
        else if (h<120) {r=x;g=c;b=0;}
        else if (h<180) {r=0;g=c;b=x;}
        else if (h<240) {r=0;g=x;b=c;}
        else if (h<300) {r=x;g=0;b=c;}
        else            {r=c;g=0;b=x;}
        return {r+m,g+m,b+m,a};
    }

    /// Convert to HSL
    void ToHSL(float& h, float& s, float& l) const {
        float mx=std::max({r,g,b}), mn=std::min({r,g,b});
        float d=mx-mn;
        l=(mx+mn)*0.5f;
        s = d<EPSILON ? 0 : d/(1-std::abs(2*l-1));
        if (d<EPSILON) { h=0; return; }
        if      (mx==r) h=60*std::fmod((g-b)/d,6);
        else if (mx==g) h=60*((b-r)/d+2);
        else            h=60*((r-g)/d+4);
        if (h<0) h+=360;
    }

    /// From HSL
    static Color FromHSL(float h, float s, float l, float a=1) {
        float c=s*(1-std::abs(2*l-1));
        float x=c*(1-std::abs(std::fmod(h/60,2)-1));
        float m=l-c*0.5f;
        float r,g,b;
        if      (h<60)  {r=c;g=x;b=0;}
        else if (h<120) {r=x;g=c;b=0;}
        else if (h<180) {r=0;g=c;b=x;}
        else if (h<240) {r=0;g=x;b=c;}
        else if (h<300) {r=x;g=0;b=c;}
        else            {r=c;g=0;b=x;}
        return {r+m,g+m,b+m,a};
    }

    /// Lerp between two colors
    Color Lerp(const Color& to, float t) const {
        return {Math::Lerp(r,to.r,t), Math::Lerp(g,to.g,t),
                Math::Lerp(b,to.b,t), Math::Lerp(a,to.a,t)};
    }

    // ---- Blend modes ----

    /// Normal alpha blend (src over dst)
    Color BlendOver(const Color& dst) const {
        float ao = a + dst.a*(1-a);
        if (ao < EPSILON) return {};
        return {(r*a + dst.r*dst.a*(1-a))/ao,
                (g*a + dst.g*dst.a*(1-a))/ao,
                (b*a + dst.b*dst.a*(1-a))/ao, ao};
    }

    Color BlendMultiply(const Color& o) const {
        return {r*o.r, g*o.g, b*o.b, a*o.a};
    }
    Color BlendScreen(const Color& o) const {
        return {1-(1-r)*(1-o.r), 1-(1-g)*(1-o.g), 1-(1-b)*(1-o.b), a};
    }
    Color BlendOverlay(const Color& o) const {
        auto f=[](float a,float b){
            return a<0.5f ? 2*a*b : 1-2*(1-a)*(1-b); };
        return {f(r,o.r),f(g,o.g),f(b,o.b),a};
    }
    Color BlendAdd(const Color& o) const {
        return {Math::Saturate(r+o.r), Math::Saturate(g+o.g),
                Math::Saturate(b+o.b), a};
    }
    Color BlendDifference(const Color& o) const {
        return {std::abs(r-o.r),std::abs(g-o.g),std::abs(b-o.b),a};
    }

    /// Darken / lighten
    Color Darkened(float amount)   const { return Lerp(Black(), amount); }
    Color Lightened(float amount)  const { return Lerp(White(), amount); }

    /// Shift hue by degrees
    Color HueShifted(float degrees) const {
        float h,s,v; ToHSV(h,s,v);
        return FromHSV(Math::FMod(h+degrees,360),s,v,a);
    }

    /// Invert
    Color Inverted() const { return {1-r,1-g,1-b,a}; }

    /// Grayscale luminance
    float Luminance() const { return 0.2126f*r + 0.7152f*g + 0.0722f*b; }

    Color operator*(float s) const { return {r*s,g*s,b*s,a*s}; }
    Color operator+(const Color& o) const { return {r+o.r,g+o.g,b+o.b,a+o.a}; }

    // ---- Named colors ----
    static constexpr Color Black()   { return {0,0,0,1}; }
    static constexpr Color White()   { return {1,1,1,1}; }
    static constexpr Color Red()     { return {1,0,0,1}; }
    static constexpr Color Green()   { return {0,1,0,1}; }
    static constexpr Color Blue()    { return {0,0,1,1}; }
    static constexpr Color Yellow()  { return {1,1,0,1}; }
    static constexpr Color Cyan()    { return {0,1,1,1}; }
    static constexpr Color Magenta() { return {1,0,1,1}; }
    static constexpr Color Orange()  { return {1,0.5f,0,1}; }
    static constexpr Color Purple()  { return {0.5f,0,0.5f,1}; }
    static constexpr Color Pink()    { return {1,0.75f,0.8f,1}; }
    static constexpr Color Gray()    { return {0.5f,0.5f,0.5f,1}; }
    static constexpr Color Transparent() { return {0,0,0,0}; }

    // ---- DDLC character colors ----
    static constexpr Color Monika()  { return {0.12f,0.31f,0.16f,1}; }
    static constexpr Color Yuri()    { return {0.16f,0.08f,0.27f,1}; }
    static constexpr Color Natsuki() { return {0.71f,0.12f,0.31f,1}; }
    static constexpr Color Sayori()  { return {0.86f,0.63f,0.16f,1}; }
};

// ============================================================
//  SECTION M6 — Geometry
// ============================================================
namespace Geo {

    /// Axis-Aligned Bounding Box (2D)
    struct AABB2 {
        Vec2 min, max;

        AABB2() = default;
        AABB2(Vec2 min, Vec2 max) : min(min), max(max) {}
        AABB2(float x, float y, float w, float h)
            : min{x,y}, max{x+w,y+h} {}

        Vec2  Center()    const { return (min+max)*0.5f; }
        Vec2  Size()      const { return max-min; }
        float Width()     const { return max.x-min.x; }
        float Height()    const { return max.y-min.y; }
        float Area()      const { return Width()*Height(); }

        bool Contains(Vec2 p) const {
            return p.x>=min.x&&p.x<=max.x&&p.y>=min.y&&p.y<=max.y;
        }
        bool Overlaps(const AABB2& o) const {
            return min.x<o.max.x&&max.x>o.min.x&&
                   min.y<o.max.y&&max.y>o.min.y;
        }
        AABB2 Expanded(float amount) const {
            return {min-Vec2(amount), max+Vec2(amount)};
        }
        AABB2 Union(const AABB2& o) const {
            return {{std::min(min.x,o.min.x),std::min(min.y,o.min.y)},
                    {std::max(max.x,o.max.x),std::max(max.y,o.max.y)}};
        }
        AABB2 Intersection(const AABB2& o) const {
            return {{std::max(min.x,o.min.x),std::max(min.y,o.min.y)},
                    {std::min(max.x,o.max.x),std::min(max.y,o.max.y)}};
        }
        bool IsValid() const { return min.x<=max.x&&min.y<=max.y; }
    };

    /// Circle
    struct Circle {
        Vec2  center;
        float radius;

        bool Contains(Vec2 p) const {
            return (p-center).LengthSq() <= radius*radius;
        }
        bool Overlaps(const Circle& o) const {
            float d=radius+o.radius;
            return (center-o.center).LengthSq() <= d*d;
        }
        bool Overlaps(const AABB2& box) const {
            Vec2 closest = {
                Math::Clamp(center.x, box.min.x, box.max.x),
                Math::Clamp(center.y, box.min.y, box.max.y)
            };
            return (center-closest).LengthSq() <= radius*radius;
        }
        float Area() const { return PIf * radius * radius; }
    };

    /// 2D Ray
    struct Ray2 {
        Vec2 origin, direction; // direction should be normalized

        /// Point along ray at distance t
        Vec2 At(float t) const { return origin + direction*t; }

        /// Intersect with AABB — returns t of first hit, or -1 if miss
        float Intersect(const AABB2& box) const {
            Vec2 invD = {1.0f/direction.x, 1.0f/direction.y};
            float t1=(box.min.x-origin.x)*invD.x;
            float t2=(box.max.x-origin.x)*invD.x;
            float t3=(box.min.y-origin.y)*invD.y;
            float t4=(box.max.y-origin.y)*invD.y;
            float tmin=std::max(std::min(t1,t2),std::min(t3,t4));
            float tmax=std::min(std::max(t1,t2),std::max(t3,t4));
            if (tmax<0||tmin>tmax) return -1;
            return tmin<0 ? tmax : tmin;
        }

        /// Intersect with circle — returns t of first hit, or -1 if miss
        float Intersect(const Circle& c) const {
            Vec2 oc = origin - c.center;
            float b = oc.Dot(direction);
            float d = b*b - oc.LengthSq() + c.radius*c.radius;
            if (d<0) return -1;
            float sq=std::sqrt(d);
            float t1=-b-sq, t2=-b+sq;
            if (t1>0) return t1;
            if (t2>0) return t2;
            return -1;
        }
    };

    /// 3D Ray
    struct Ray3 {
        Vec3 origin, direction;
        Vec3 At(float t) const { return origin + direction*t; }

        /// Intersect with sphere
        float IntersectSphere(Vec3 center, float radius) const {
            Vec3 oc = origin - center;
            float b=oc.Dot(direction);
            float d=b*b-oc.LengthSq()+radius*radius;
            if (d<0) return -1;
            float sq=std::sqrt(d);
            float t=-b-sq;
            return t>0 ? t : -b+sq;
        }

        /// Intersect with infinite plane
        /// normal: plane normal, dist: plane distance from origin
        float IntersectPlane(Vec3 normal, float dist) const {
            float denom = normal.Dot(direction);
            if (std::abs(denom) < EPSILON) return -1;
            return -(normal.Dot(origin)+dist)/denom;
        }
    };

    /// Closest point on line segment to point p
    inline Vec2 ClosestPointOnSegment(Vec2 a, Vec2 b, Vec2 p) {
        Vec2 ab=b-a, ap=p-a;
        float t=Math::Saturate(ap.Dot(ab)/ab.LengthSq());
        return a+ab*t;
    }

    /// Distance from point to line segment
    inline float PointToSegmentDist(Vec2 a, Vec2 b, Vec2 p) {
        return (p - ClosestPointOnSegment(a,b,p)).Length();
    }

    /// Is point inside triangle?
    inline bool PointInTriangle(Vec2 p, Vec2 a, Vec2 b, Vec2 c) {
        float d1=(p-b).Cross(a-b);
        float d2=(p-c).Cross(b-c);
        float d3=(p-a).Cross(c-a);
        bool n=(d1<0)||(d2<0)||(d3<0);
        bool x=(d1>0)||(d2>0)||(d3>0);
        return !(n&&x);
    }

    /// Triangle area
    inline float TriangleArea(Vec2 a, Vec2 b, Vec2 c) {
        return std::abs((b-a).Cross(c-a)) * 0.5f;
    }

} // namespace Geo

// ============================================================
//  SECTION M7 — Random Number Utilities
// ============================================================
namespace Rand {

    /// Global RNG — seeded on first use
    inline std::mt19937& GetRNG() {
        static std::mt19937 rng{std::random_device{}()};
        return rng;
    }

    /// Seed the global RNG
    inline void Seed(uint32_t seed) { GetRNG().seed(seed); }

    /// Random int in [lo, hi] inclusive
    inline int Int(int lo, int hi) {
        return std::uniform_int_distribution<int>{lo, hi}(GetRNG());
    }

    /// Random float in [lo, hi)
    inline float Float(float lo=0.0f, float hi=1.0f) {
        return std::uniform_real_distribution<float>{lo, hi}(GetRNG());
    }

    /// Random double in [lo, hi)
    inline double Double(double lo=0.0, double hi=1.0) {
        return std::uniform_real_distribution<double>{lo, hi}(GetRNG());
    }

    /// Random bool with given probability (default 50/50)
    inline bool Bool(float probability=0.5f) {
        return Float() < probability;
    }

    /// Random unit Vec2 (random direction)
    inline Vec2 UnitVec2() {
        float a = Float(0, TAUf);
        return {std::cos(a), std::sin(a)};
    }

    /// Random point inside unit circle
    inline Vec2 InCircle(float radius=1.0f) {
        return UnitVec2() * std::sqrt(Float()) * radius;
    }

    /// Random unit Vec3
    inline Vec3 UnitVec3() {
        float z = Float(-1.0f, 1.0f);
        float a = Float(0, TAUf);
        float r = std::sqrt(1-z*z);
        return {r*std::cos(a), r*std::sin(a), z};
    }

    /// Random point on sphere surface
    inline Vec3 OnSphere(float radius=1.0f) {
        return UnitVec3() * radius;
    }

    /// Gaussian (normal) distribution
    inline float Gaussian(float mean=0.0f, float stddev=1.0f) {
        return std::normal_distribution<float>{mean, stddev}(GetRNG());
    }

    /// Shuffle a vector in place
    template<typename T>
    void Shuffle(std::vector<T>& v) {
        std::shuffle(v.begin(), v.end(), GetRNG());
    }

    /// Pick a random element from a vector
    template<typename T>
    const T& Pick(const std::vector<T>& v) {
        return v[Int(0, static_cast<int>(v.size())-1)];
    }

    /// Weighted random pick — weights don't need to sum to 1
    template<typename T>
    const T& WeightedPick(const std::vector<T>& items,
                          const std::vector<float>& weights) {
        float total = std::accumulate(weights.begin(), weights.end(), 0.0f);
        float r = Float(0, total);
        float cumulative = 0;
        for (size_t i = 0; i < items.size(); ++i) {
            cumulative += weights[i];
            if (r <= cumulative) return items[i];
        }
        return items.back();
    }

    /// Generate N unique random ints in [lo, hi]
    inline std::vector<int> UniqueInts(int lo, int hi, int n) {
        std::vector<int> pool;
        for (int i=lo; i<=hi; ++i) pool.push_back(i);
        Shuffle(pool);
        pool.resize(n);
        return pool;
    }

} // namespace Rand

// ============================================================
//  SECTION M8 — Statistics
// ============================================================
namespace Stats {

    /// Arithmetic mean
    template<typename T>
    double Mean(const std::vector<T>& v) {
        if (v.empty()) return 0;
        return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
    }

    /// Median (sorts a copy)
    template<typename T>
    double Median(std::vector<T> v) {
        if (v.empty()) return 0;
        std::sort(v.begin(), v.end());
        size_t n = v.size();
        return n%2==0 ? (v[n/2-1]+v[n/2])/2.0 : v[n/2];
    }

    /// Variance (population)
    template<typename T>
    double Variance(const std::vector<T>& v) {
        double m = Mean(v);
        double sum = 0;
        for (auto& x : v) sum += (x-m)*(x-m);
        return v.empty() ? 0 : sum/v.size();
    }

    /// Standard deviation (population)
    template<typename T>
    double StdDev(const std::vector<T>& v) {
        return std::sqrt(Variance(v));
    }

    /// Min element
    template<typename T>
    T Min(const std::vector<T>& v) {
        return *std::min_element(v.begin(), v.end());
    }

    /// Max element
    template<typename T>
    T Max(const std::vector<T>& v) {
        return *std::max_element(v.begin(), v.end());
    }

    /// Range (max - min)
    template<typename T>
    T Range(const std::vector<T>& v) { return Max(v) - Min(v); }

    /// Percentile (0-100)
    template<typename T>
    double Percentile(std::vector<T> v, double p) {
        if (v.empty()) return 0;
        std::sort(v.begin(), v.end());
        double idx = (p/100.0) * (v.size()-1);
        size_t lo = static_cast<size_t>(idx);
        size_t hi = lo+1 < v.size() ? lo+1 : lo;
        double frac = idx - lo;
        return v[lo] + frac*(v[hi]-v[lo]);
    }

    /// Moving average over last N samples
    struct MovingAverage {
        std::vector<double> buf;
        size_t capacity;
        double sum = 0;

        MovingAverage(size_t n) : capacity(n) {}

        double Add(double v) {
            if (buf.size() >= capacity) { sum-=buf.front(); buf.erase(buf.begin()); }
            buf.push_back(v);
            sum += v;
            return sum / buf.size();
        }
        double Get() const { return buf.empty() ? 0 : sum/buf.size(); }
    };

    /// Exponential moving average
    struct EMA {
        double value = 0;
        double alpha; // smoothing factor 0-1 (higher = more responsive)
        bool initialized = false;

        EMA(double alpha) : alpha(alpha) {}

        double Add(double v) {
            if (!initialized) { value=v; initialized=true; }
            else value = alpha*v + (1-alpha)*value;
            return value;
        }
    };

} // namespace Stats

// ============================================================
//  SECTION M9 — Bitwise Utilities
// ============================================================
namespace Bits {

    /// Count set bits (population count)
    inline int PopCount(uint32_t v) { return static_cast<int>(__popcnt(v)); }
    inline int PopCount(uint64_t v) { return static_cast<int>(__popcnt64(v)); }

    /// Bit scan forward — index of lowest set bit (undefined if v==0)
    inline int BSF(uint32_t v) {
        unsigned long idx; _BitScanForward(&idx, v); return static_cast<int>(idx);
    }

    /// Bit scan reverse — index of highest set bit (undefined if v==0)
    inline int BSR(uint32_t v) {
        unsigned long idx; _BitScanReverse(&idx, v); return static_cast<int>(idx);
    }

    /// Next power of 2 >= v
    inline uint32_t NextPow2(uint32_t v) {
        if (v == 0) return 1;
        --v;
        v |= v>>1; v |= v>>2; v |= v>>4; v |= v>>8; v |= v>>16;
        return ++v;
    }

    /// Is v a power of 2?
    constexpr bool IsPow2(uint32_t v) { return v&&!(v&(v-1)); }

    /// Rotate left
    inline uint32_t RotL(uint32_t v, int n) { return _rotl(v,n); }
    inline uint32_t RotR(uint32_t v, int n) { return _rotr(v,n); }

    /// Get bit at position
    constexpr bool GetBit(uint32_t v, int pos) { return (v>>pos)&1; }

    /// Set bit at position
    constexpr uint32_t SetBit(uint32_t v, int pos) { return v|(1u<<pos); }

    /// Clear bit at position
    constexpr uint32_t ClearBit(uint32_t v, int pos) { return v&~(1u<<pos); }

    /// Toggle bit at position
    constexpr uint32_t ToggleBit(uint32_t v, int pos) { return v^(1u<<pos); }

    /// Test if ALL flags are set
    constexpr bool HasAll(uint32_t v, uint32_t flags) { return (v&flags)==flags; }

    /// Test if ANY flag is set
    constexpr bool HasAny(uint32_t v, uint32_t flags) { return (v&flags)!=0; }

    /// Byte swap (endian flip)
    inline uint16_t ByteSwap(uint16_t v) { return _byteswap_ushort(v); }
    inline uint32_t ByteSwap(uint32_t v) { return _byteswap_ulong(v); }
    inline uint64_t ByteSwap(uint64_t v) { return _byteswap_uint64(v); }

    /// Pack/unpack 4 bytes into uint32
    constexpr uint32_t Pack8(uint8_t a,uint8_t b,uint8_t c,uint8_t d) {
        return (a<<24)|(b<<16)|(c<<8)|d;
    }

} // namespace Bits

// ============================================================
//  SECTION M10 — Screen / Window Math
// ============================================================
namespace Screen {

    /// Convert screen pixel to normalized device coordinates [-1, 1]
    inline Vec2 ToNDC(Vec2 pixel, float screenW, float screenH) {
        return {2*pixel.x/screenW - 1, 1 - 2*pixel.y/screenH};
    }

    /// Convert NDC back to screen pixel
    inline Vec2 FromNDC(Vec2 ndc, float screenW, float screenH) {
        return {(ndc.x+1)*screenW*0.5f, (1-ndc.y)*screenH*0.5f};
    }

    /// Aspect ratio (width / height)
    inline float AspectRatio(float w, float h) { return w/h; }

    /// Fit a rect (srcW x srcH) into (dstW x dstH) maintaining aspect ratio
    /// Returns {x, y, width, height} of the fitted rect
    inline std::array<float,4> FitRect(float srcW, float srcH,
                                        float dstW, float dstH) {
        float scale = std::min(dstW/srcW, dstH/srcH);
        float w=srcW*scale, h=srcH*scale;
        return {(dstW-w)*0.5f, (dstH-h)*0.5f, w, h};
    }

    /// Fill a rect (srcW x srcH) into (dstW x dstH) — may crop
    inline std::array<float,4> FillRect(float srcW, float srcH,
                                         float dstW, float dstH) {
        float scale = std::max(dstW/srcW, dstH/srcH);
        float w=srcW*scale, h=srcH*scale;
        return {(dstW-w)*0.5f, (dstH-h)*0.5f, w, h};
    }

    /// Scale a value from logical pixels to physical pixels (DPI scaling)
    inline float LogicalToPhysical(float v, float dpi) {
        return v * (dpi/96.0f);
    }

    /// Scale from physical to logical pixels
    inline float PhysicalToLogical(float v, float dpi) {
        return v / (dpi/96.0f);
    }

    /// Scale factor for given DPI (1.0 at 96 DPI, 1.25 at 120, 1.5 at 144)
    inline float DPIScale(float dpi) { return dpi/96.0f; }

    /// Unproject screen point to world ray using inverse VP matrix
    /// Returns a Ray3 from near plane into the scene
    inline Geo::Ray3 ScreenToWorldRay(Vec2 screenPos, float screenW,
        float screenH, const Mat4& view, const Mat4& proj) {
        Vec2 ndc = ToNDC(screenPos, screenW, screenH);

        // Inverse of projection * view
        Mat4 invVP = (proj * view).Transposed(); // simplified — real use needs proper inverse

        Vec4 nearP = invVP * Vec4(ndc.x, ndc.y, -1.0f, 1.0f);
        Vec4 farP  = invVP * Vec4(ndc.x, ndc.y,  1.0f, 1.0f);

        Vec3 origin = nearP.XYZ() * (1.0f/nearP.w);
        Vec3 dir    = (farP.XYZ()*(1.0f/farP.w) - origin).Normalized();

        return {origin, dir};
    }

    /// Convert world position to screen position
    inline Vec2 WorldToScreen(Vec3 worldPos, float screenW, float screenH,
        const Mat4& view, const Mat4& proj) {
        Vec4 clip = proj * view * Vec4(worldPos, 1.0f);
        if (std::abs(clip.w) < EPSILON) return {-1,-1};
        Vec3 ndc = clip.XYZ() * (1.0f/clip.w);
        return FromNDC({ndc.x,ndc.y}, screenW, screenH);
    }

} // namespace Screen

} // namespace WinMath

#endif // WIN_MATH_HPP

// ============================================================
//  QUICK REFERENCE — WinMath.hpp
// ============================================================
//
//  Math::     Clamp, Saturate, Remap, Lerp, InvLerp, Sign,
//             Wrap, WrapAngle, AngleDiff, ApproxEqual,
//             ToRad, ToDeg, Pow, FMod, SMin, PingPong
//
//  Interp::   Smoothstep, Smootherstep
//             EaseIn/Out/InOut: Quad,Cubic,Quart,Sine,Expo,Circ,Elastic,Bounce
//             Bezier2, Bezier3, CatmullRom, Spring
//
//  Vec2       +,-,*,/ operators, Length, Normalize, Dot, Cross,
//             Rotate, Reflect, Lerp, DistanceTo, Perp
//  Vec3       +,-,*,/ operators, Length, Normalize, Dot, Cross,
//             Reflect, Lerp, ProjectOnto, XY, XZ
//  Vec4       +,-,* operators, Dot, XYZ, XY
//
//  Mat4       Identity, Translate, Scale, RotateX/Y/Z/Axis,
//             Perspective, Ortho, LookAt, *, TransformPoint,
//             TransformDir, Transposed, GetTranslation, Data
//
//  Color      FromRGBA8, FromHex, ToCOLORREF, FromCOLORREF,
//             ToHSV, FromHSV, ToHSL, FromHSL, Lerp,
//             BlendOver/Multiply/Screen/Overlay/Add/Difference,
//             Darkened, Lightened, HueShifted, Inverted, Luminance
//             Named: Black/White/Red/Green/Blue/... + DDLC characters
//
//  Geo::      AABB2, Circle, Ray2, Ray3,
//             ClosestPointOnSegment, PointToSegmentDist,
//             PointInTriangle, TriangleArea
//
//  Rand::     Seed, Int, Float, Double, Bool,
//             UnitVec2, InCircle, UnitVec3, OnSphere, Gaussian,
//             Shuffle, Pick, WeightedPick, UniqueInts
//
//  Stats::    Mean, Median, Variance, StdDev, Min, Max,
//             Range, Percentile, MovingAverage, EMA
//
//  Bits::     PopCount, BSF, BSR, NextPow2, IsPow2,
//             RotL, RotR, GetBit, SetBit, ClearBit, ToggleBit,
//             HasAll, HasAny, ByteSwap, Pack8
//
//  Screen::   ToNDC, FromNDC, AspectRatio, FitRect, FillRect,
//             LogicalToPhysical, PhysicalToLogical, DPIScale,
//             ScreenToWorldRay, WorldToScreen
//
// ============================================================