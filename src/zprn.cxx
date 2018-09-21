/**
 * zprn.cxx
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#include "zprn.hpp"
#include "memut.hpp"

zprn_v1::zprn_v1() noexcept : zprn_mgc(0), zprn_ver(1), zprn_cmd(0), zprn_prio(0)
  { zeroify(zprn_un); }

bool zprn_v1::valid() const noexcept {
  if(zprn_mgc || zprn_ver != 1)
    return false;

  switch(zprn_cmd) {
    case ZPRN_ROUTEMOD:
    case ZPRN_CONNMGMT:
    case ZPRN_RESULT:
      return true;

    default:
      return false;
  }
}

bool zprn_v2hdr::valid() const noexcept {
  if(zprn_mgc || zprn_ver != 2)
    return false;
  return true;
}

size_t zprn_v2::get_needed_size() const noexcept {
  return 2 + route.get_tflen();
}
