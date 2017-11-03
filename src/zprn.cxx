/**
 * resolve.cxx
 * (C) 2017 Erik Zscheile.
 * License: GPL-3
 **/

#include <string.h>
#include "main.hpp"
#include "zprn.hpp"

zprn::zprn()
 : zprn_mgc(0), zprn_ver(0), zprn_cmd(0) {
  memset(&zprn_un, 0, sizeof(zprn_un));
}

bool zprn::valid() const noexcept {
  if(zprn_mgc || zprn_ver)
    return false;

  switch(zprn_cmd) {
    case 0:
      return true;

    default:
      return false;
  }
}

void zprn::send(const std::set<uint32_t> &peers) const {
  set_ip_df(static_cast<uint8_t>(0));

  for(auto &&peer : peers)
    send_packet(peer, reinterpret_cast<const char *>(this), sizeof(*this));
}
