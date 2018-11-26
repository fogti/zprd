/**
 * zprn.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <iAFa.hpp>
#include <inttypes.h>

// command
#define ZPRN_ROUTEMOD 0x00
#define ZPRN_CONNMGMT 0x01
#define ZPRN_RESULT   0x02
#define ZPRN2_PROBE 0x03
// priority / negation / hop count
#define ZPRN_CONNMGMT_OPEN   0x00
#define ZPRN_CONNMGMT_CLOSE  0xFF
#define ZPRN_RESULT_OK       0x00
#define ZPRN_RESULT_FATERR   0xFF

#pragma pack(push, 1)
struct zprn_v2hdr final {
  uint8_t zprn_mgc;
  uint8_t zprn_ver;
  uint8_t z__unused0;
  uint8_t z__unused1;

  bool valid() const noexcept;
};

struct zprn_v2 final {
  uint8_t zprn_cmd;  // command
  uint8_t zprn_prio; // priority
  inner_addr_t route;

  // get real online needed size
  size_t get_needed_size() const noexcept;
};
#pragma pack(pop)
