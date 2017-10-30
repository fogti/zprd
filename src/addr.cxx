/**
 * zprd / addr.cxx
 * (C) 2017 Erik Zscheile.
 * License: GPL-3
 **/

#include "addr.hpp"

bool operator==(const in_addr &a, const in_addr &b) noexcept {
  return (a.s_addr == b.s_addr);
}

bool operator!=(const in_addr &a, const in_addr &b) noexcept {
  return !(a == b);
}

bool is_broadcast_addr(const struct in_addr &a) noexcept {
  const in_addr_t ip_raddr = ntohl(a.s_addr);
  return (ip_raddr == INADDR_ANY || ip_raddr == INADDR_BROADCAST);
}

uint32_t cidr_to_netmask(const uint8_t suffix) noexcept {
  return htonl(~(0xffffffff >> suffix));
}
