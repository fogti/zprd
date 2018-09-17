/**
 * backtrace.h
 * (C) 2018 Erik Zscheile.
 * License: dual licensed under MIT and GPL-2+
 **/

#pragma once
#ifdef __cplusplus
extern "C" {
#endif
  void setup_sigsegv_handler(void);
#ifdef __cplusplus
}
#endif
