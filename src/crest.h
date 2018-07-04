/**
 * crest.h
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <inttypes.h>
#include <signal.h>
#include <cwa_noexcept.h>
#ifdef __cplusplus
extern "C" {
#endif
  uint16_t in_cksum(const uint16_t *ptr, int nbytes) noexcept;

  typedef void (*sighandler_t)(int);
  void my_signal(const int sig_nr, const sighandler_t sig_handler) noexcept;
#ifdef __cplusplus
}
template<typename T>
uint16_t IN_CKSUM(const T *const ptr) noexcept {
  return in_cksum(reinterpret_cast<const uint16_t*>(ptr), sizeof(T));
}
#endif
