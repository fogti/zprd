/**
 * zprn.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-3
 **/
#pragma once
#include <inttypes.h>
#include <vector>

struct zprn {
  uint8_t zprn_mgc;
  uint8_t zprn_ver;

  // zprn_cmd = command
  uint8_t zprn_cmd;
#define ZPRN_ROUTEMOD 0x00
#define ZPRN_CONNMGMT 0x01
#define ZPRN_RESULT   0x02

  // zprn_prio = priority
  uint8_t zprn_prio;
#define ZPRN_ROUTEMOD_DELETE 0xFF
#define ZPRN_CONNMGMT_OPEN   0x00
#define ZPRN_CONNMGMT_CLOSE  0xFF
#define ZPRN_RESULT_OK       0x00
#define ZPRN_RESULT_FATERR   0xFF

  union {
    struct {
      uint32_t dsta;
    } route;
  } zprn_un;

  zprn() noexcept;
  bool valid() const noexcept;
};
