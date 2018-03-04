/**
 * remote_peer.cxx
 * (C) 2017 Erik Zscheile.
 * License: GPL-3
 **/

#include "remote_peer.hpp"
#include "zprd_conf.hpp"

remote_peer_t::remote_peer_t() noexcept
  : seen(time(0)), cent(-1) { }

remote_peer_t::remote_peer_t(const size_t cfgent) noexcept
  : seen(time(0)), cent(static_cast<ssize_t>(cfgent)) { }

void remote_peer_t::refresh() noexcept {
  seen = time(0);
}

const char *remote_peer_t::cfgent_name() const {
  if(cent < 0) return "-";
  const auto &r = zprd_conf.remotes;
  const auto ce = static_cast<size_t>(cent);
  if(ce >= r.size()) return "####";
  return r[ce].c_str();
}
