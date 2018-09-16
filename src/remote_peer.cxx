/**
 * remote_peer.cxx
 *  This file contains the implementation of the 'outer address family abstraction'
 * (C) 2017 Erik Zscheile.
 * License: GPL-2+
 **/

#include "remote_peer.hpp"
#include "AFa.hpp"
#include <config.h>

#include <stdio.h>
#include <arpa/inet.h> // sockaddr_in, INADDR_ANY, in6addr_any
#include <string.h>

remote_peer_t::remote_peer_t() noexcept
  { memset(&saddr, 0, sizeof(saddr)); }

remote_peer_t::remote_peer_t(const struct sockaddr_storage &sas) noexcept
  { set_saddr(sas, false); }

remote_peer_t::remote_peer_t(remote_peer_t &&o) noexcept
  { set_saddr(o.saddr, false); }

[[gnu::hot]]
static int compare_peers(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept {
  return AFa_sa_compare(lhs.saddr, rhs.saddr);
}

bool operator==(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return !compare_peers(lhs, rhs); }
bool operator!=(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return compare_peers(lhs, rhs); }
bool operator<(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return compare_peers(lhs, rhs) < 0; }
bool operator>(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return compare_peers(lhs, rhs) > 0; }

using std::string;

auto remote_peer_t::addr2string() const -> string {
  const sa_family_t sa_fam = saddr.ss_family;
  return AFa_addr2string(sa_fam, AFa_gp_addr(saddr)) + ':' + AFa_port2string(sa_fam, AFa_gp_port(saddr));
}

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
    memcpy(&saddr, &sas, sizeof(saddr));
  }
}

#define SA_XXX_PTR(PROTO,WHAT) (&reinterpret_cast<struct sockaddr_##PROTO*>(&saddr)->s##PROTO##_##WHAT)

// used by src/main.cxx:setup_server_fd
bool remote_peer_t::set2catchall() noexcept {
  switch(saddr.ss_family) {
    case AF_INET:
      SA_XXX_PTR(in, addr)->s_addr = htonl(INADDR_ANY);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      *SA_XXX_PTR(in6, addr) = in6addr_any;
      break;
#endif
#ifdef USE_IPX
# error "IPX is not supported in remote_peer_t::set2catchall"
//    FIXME -- low importance
    case AF_IPX:
      SA_XXX_PTR(ipx, addr) = ...IDK...;
      break;
#endif
    default:
      break;
  }
  return true;
}

#undef SA_XXX_PTR

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
