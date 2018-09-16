/**
 * remote_peer_detail.cxx
 * (C) 2017 Erik Zscheile.
 * License: GPL-2+
 **/

#include "remote_peer.hpp"

extern time_t last_time;

remote_peer_detail_t::remote_peer_detail_t() noexcept
  : seen(last_time), cent(0), to_discard(false) { }

remote_peer_detail_t::remote_peer_detail_t(const sockaddr_storage &sas) noexcept
  : remote_peer_t(sas), seen(last_time), cent(0), to_discard(false) { }

remote_peer_detail_t::remote_peer_detail_t(const remote_peer_t &o) noexcept
  : remote_peer_detail_t(o.get_saddr()) { }

remote_peer_detail_t::remote_peer_detail_t(remote_peer_t &&o) noexcept
  : remote_peer_detail_t(o.saddr) { }

remote_peer_detail_t::remote_peer_detail_t(const remote_peer_t &o, const size_t cfgent) noexcept
  : remote_peer_detail_t(o) { cent = cfgent + 1; }

remote_peer_detail_t::remote_peer_detail_t(remote_peer_t &&o, const size_t cfgent) noexcept
  : remote_peer_detail_t(std::move(o)) { cent = cfgent + 1; }

#include "zprd_conf.hpp"

const char *remote_peer_detail_t::cfgent_name() const noexcept {
  if(cent < 1) return "-";
  const auto &r = zprd_conf.remotes;
  const size_t ce = cent - 1;
  return (ce >= r.size()) ? "####" : r[ce].c_str();
}
