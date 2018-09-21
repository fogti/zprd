/**
 * memut.hpp
 * (C) 2018 Erik Zscheile.
 * License: MIT
 **/
#pragma once
#include <config.h>
#include <string.h>
#include <algorithm>

template<typename T>
static inline void zeroify(T &obj) noexcept
  { memset(&obj, 0, sizeof(T)); }

static inline void zeroify_offset(void *const __restrict ptr, const size_t whole, const size_t snip) noexcept
  { memset(static_cast<char*>(ptr) + snip, 0, whole - snip); }

template<typename T>
static inline void partial_memcpy(T *const __restrict__ dest, const T *const __restrict__ src, const size_t snip) noexcept {
  static_assert(sizeof(T) != 1); // avoid misuse of function
  const size_t sanit_snip = std::min(sizeof(T), snip);
  memcpy(dest, src, sanit_snip);
  zeroify_offset(dest, sizeof(T), sanit_snip);
}

template<size_t WHOLE>
static inline void partial_memcpy_bytes(char dest[WHOLE], const char *const __restrict__ src, const size_t snip) {
  const size_t sanit_snip = std::min(WHOLE, snip);
  memcpy(dest, src, sanit_snip);
  zeroify_offset(dest, WHOLE, sanit_snip);
}

template<size_t WHOLE, typename T>
static inline void partial_memcpy_lazy(char dest[WHOLE], const T *const __restrict__ src) noexcept {
  constexpr const size_t snip = sizeof(T);
  static_assert(WHOLE >= snip);
  memcpy(dest, src, snip);
  zeroify_offset(dest, WHOLE, snip);
}

template<typename T>
static inline void whole_memcpy(T *const __restrict__ dest, const T *const __restrict__ src) noexcept
  { memcpy(dest, src, sizeof(T)); }

template<typename T>
static inline void whole_memcpy_lazy(char dest[sizeof(T)], const T *const __restrict__ src) noexcept
  { memcpy(dest, src, sizeof(T)); }

// use size of src as real size
template<typename Ta, typename Tb>
static inline void memcpy_from(Ta *const __restrict__ dest, const Tb *const __restrict__ src) noexcept {
  static_assert(sizeof(Tb) != 1); // avoid misuse of function
  memcpy(dest, src, sizeof(Tb));
}

// use size of dest as real size
template<typename Ta, typename Tb>
static inline void memcpy_to(Ta *const __restrict__ dest, const Tb *const __restrict__ src) noexcept {
  static_assert(sizeof(Ta) != 1); // avoid misuse of function
  memcpy(dest, src, sizeof(Ta));
}
