/**
 * remote_peer.cxx
 *  This file contains the implementation of the 'outer address family abstraction'
 * (C) 2017 Erik Zscheile.
 * License: GPL-2+
 **/

#include "remote_peer.hpp"
#include <config.h>
#include <zprd_conf.hpp>

#include <stdio.h>
#include <arpa/inet.h>
#include <endian.h>
#include <string.h>

remote_peer_t::remote_peer_t() noexcept
  { memset(&saddr, 0, sizeof(saddr)); }

remote_peer_t::remote_peer_t(const struct sockaddr_storage &sas) noexcept
  { set_saddr(sas, false); }

remote_peer_t::remote_peer_t(remote_peer_t &&o) noexcept
  { set_saddr(o.saddr, false); }

static int compare_peers(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept
  { return memcmp(&lhs.saddr, &rhs.saddr, sizeof(lhs.saddr)); }

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
#define SA_XXX_PTR(PROTO,WHAT) (&reinterpret_cast<const struct sockaddr_##PROTO*>(&saddr)->s##PROTO##_##WHAT)
#define SA_PORT_PTR(PROTO) SA_XXX_PTR(PROTO,port)
  char buf[1058] = {0}; // the buffer should be large enough to hold any host addr + port number
  const uint16_t *sanport = 0;

  switch(saddr.ss_family) {
    case AF_INET:
#ifdef USE_IPV6
    case AF_INET6:
      sanport = (saddr.ss_family == AF_INET) ? SA_XXX_PTR(in, port) : SA_XXX_PTR(in6, port)
#else
      sanport = SA_XXX_PTR(in, port)
#endif
        ;
      inet_ntop(saddr.ss_family, SA_XXX_PTR(in, addr), buf, sizeof(buf));
      break;
/*
    case AF_IPX:
      snprintf(buf, sizeof(buf), "%s", ipx_ntoa(*SA_XXX_PTR(ipx, addr)));
      sanport = SA_XXX_PTR(ipx, port);
      break;
 */
    default:
      return "-unsupported-AF-";
  }

  char *portptr = 0;
  // portptr = first null byte in buf
  for(char * i = buf; i < buf + sizeof(buf); ++i)
    if(!*i) {
      portptr = i;
      goto handle_port;
    }
  return {buf};

 handle_port:
  {
    *(portptr++) = ':';
    const size_t max_port_size = (buf + sizeof(buf)) - portptr;

    // convert the port number to a string
    // assume portlen = 2
    snprintf(portptr, max_port_size, "%u", (unsigned) ntohs(*sanport));
  }

  return {buf};
#undef SA_PORT_PTR
#undef SA_XXX_PTR
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
/*    FIXME
    case AF_IPX:
      SA_XXX_PTR(ipx, addr) = ...IDK...;
      break;
 */
    default:
      break;
  }
  return true;
}

void remote_peer_t::set_port(const uint16_t port, const bool do_lock) noexcept {
  if(do_lock) {
    std::unique_lock<_mtx_t> lock(_mtx);
    // single self-recursion
    set_port(port, false);
    return;
  }
  uint16_t *portptr = 0;
  switch(saddr.ss_family) {
    case AF_INET:
      portptr = SA_XXX_PTR(in, port);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      portptr = SA_XXX_PTR(in6, port);
      break;
#endif
/*
    case AF_IPX:
      portptr = SA_XXX_PTR(ipx, port);
      break;
 */
    default:
      fprintf(stderr, "NOTICE: remote_peer::set_port: unsupported address family %u\n", static_cast<unsigned>(saddr.ss_family));
  }
  if(portptr)
    *portptr = htons(port);
}

#undef SA_XXX_PTR
