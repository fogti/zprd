/**
 * remote_peer.cxx
 *  This file contains the implementation of the 'outer address family abstraction'
 * (C) 2017 Erik Zscheile.
 * License: GPL-2+
 **/

#include "remote_peer.hpp"
#include "oAFa.hpp"
#include <zs/ll/memut.hpp>

#include <stdio.h>
#include <arpa/inet.h> // sockaddr_in, INADDR_ANY, in6addr_any
#include <string.h>

remote_peer_t::remote_peer_t(const struct sockaddr_storage &sas) noexcept
  { set_saddr(sas, false); }

remote_peer_t::remote_peer_t(remote_peer_t &&o) noexcept
  { set_saddr(o.saddr, false); }

[[gnu::hot]]
static inline int compare_peers(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return AFa_sa_compare(lhs.saddr, rhs.saddr); }

bool operator==(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return !compare_peers(lhs, rhs); }
bool operator!=(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return compare_peers(lhs, rhs); }
bool operator<(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return compare_peers(lhs, rhs) < 0; }

auto remote_peer_t::get_saddr() const noexcept -> sockaddr_storage {
  std::shared_lock<_mtx_t> lock(_mtx);
  return saddr;
}

void remote_peer_t::set_saddr(const sockaddr_storage &sas, const bool do_lock) noexcept {
  if(do_lock) {
    std::unique_lock<_mtx_t> lock(_mtx);
    // single self-recursion
    set_saddr(sas, false);
  } else {
    whole_memcpy(&saddr, &sas);
  }
}

void remote_peer_t::set_port(const uint16_t port, const bool do_lock) noexcept {
  if(do_lock) {
    std::unique_lock<_mtx_t> lock(_mtx);
    // single self-recursion
    set_port(port, false);
    return;
  }
  if(uint16_t *portptr = AFa_gp_port(saddr))
    *portptr = htons(port);
  else
    fprintf(stderr, "NOTICE: remote_peer::set_port: unsupported address family %u\n", static_cast<unsigned>(saddr.ss_family));
}

void remote_peer_t::set_port_if_unset(const uint16_t port, const bool do_lock) noexcept {
  if(do_lock) {
    std::unique_lock<_mtx_t> lock(_mtx);
    // single self-recursion
    set_port_if_unset(port, false);
    return;
  }
  if(uint16_t *portptr = AFa_gp_port(saddr)) {
    if(!*portptr)
      *portptr = htons(port);
  } else {
    fprintf(stderr, "NOTICE: remote_peer::set_port: unsupported address family %u\n", static_cast<unsigned>(saddr.ss_family));
  }
}
