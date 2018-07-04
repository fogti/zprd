/**
 * remote_peer.cxx
 * (C) 2017 Erik Zscheile.
 * License: GPL-2+
 **/

#include "remote_peer.hpp"
#include "zprd_conf.hpp"

extern time_t last_time;

remote_peer_t::remote_peer_t() noexcept
  : seen(last_time), cent(0) { }

remote_peer_t::remote_peer_t(const size_t cfgent) noexcept
  : seen(last_time), cent(cfgent + 1) { }

const char *remote_peer_t::cfgent_name() const noexcept {
  if(cent < 1) return "-";
  const auto &r = zprd_conf.remotes;
  const size_t ce = cent - 1;
  if(ce >= r.size()) return "####";
  return r[ce].c_str();
}
