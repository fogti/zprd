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

remote_peer_t::remote_peer_t(const in_addr_t &x) noexcept {
  saddr.ss_family = AF_INET;
  const auto my_sa = reinterpret_cast<struct sockaddr_in*>(&saddr);
  my_sa->sin_addr.s_addr = x;
  my_sa->sin_port = zprd_conf.data_port;
}

remote_peer_t::remote_peer_t(const in_addr &x) noexcept
  : remote_peer_t(x.s_addr) { }

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
  uint16_t portlen = 0;
  const void *sanport = 0;

  switch(saddr.ss_family) {
    case AF_INET:
#ifdef USE_IPV6
    case AF_INET6:
      sanport = (saddr.sa_family == AF_INET) ? SA_XXX_PTR(in, port) : SA_XXX_PTR(in6, port)
#else
      sanport = SA_XXX_PTR(in, port)
#endif
        ;
      inet_ntop(saddr.ss_family, SA_XXX_PTR(in, addr), buf, sizeof(buf));
      portlen = 2;
      break;
/*
    case AF_IPX:
      snprintf(buf, sizeof(buf), "%s", ipx_ntoa(*SA_XXX_PTR(ipx, addr)));
      portlen = 2;
      sanport = SA_XXX_PTR(ipx, port);
 */
    default:
      return "-unsupported-AF-";
  }
  if(!portlen) return {buf};

  char *portptr = 0;
  // portptr = first null byte in buf
  for(char * i = buf; i < buf + sizeof(buf); ++i)
    if(!*i) {
      portptr = i;
      break;
    }

  if(!portptr) return {buf};

  *(portptr++) = ':';
  const size_t max_port_size = (buf + sizeof(buf)) - portptr;

  // convert the port number to a string
  switch(portlen) {
    case 1:
      snprintf(portptr, max_port_size, "%u"  , (unsigned)      *static_cast<const uint8_t*>(sanport));
      break;
    case 2:
      snprintf(portptr, max_port_size, "%u"  , (unsigned)      ntohs(*static_cast<const uint16_t*>(sanport)));
      break;
    case 4:
      snprintf(portptr, max_port_size, "%lu" , (unsigned long) ntohl(*static_cast<const uint32_t*>(sanport)));
      break;
    case 8:
      snprintf(portptr, max_port_size, "%llu", (unsigned long long) be64toh(*static_cast<const uint64_t*>(sanport)));
      break;
    default:
      snprintf(portptr, max_port_size, "-unsupported-portsiz-");
      break;
  }

  return {buf};
#undef SA_PORT
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
