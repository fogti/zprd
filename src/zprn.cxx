/**
 * zprn.cxx
 * (C) 2018 Erik Zscheile.
 * License: GPL-3
 **/

#include <string.h>
#include "zprn.hpp"

zprn::zprn() noexcept : zprn_mgc(0), zprn_ver(1), zprn_cmd(0), zprn_prio(0) {
  memset(&zprn_un, 0, sizeof(zprn_un));
}

bool zprn::valid() const noexcept {
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
