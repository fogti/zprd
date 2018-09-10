/**
 * addr.hpp
 * (C) 2018 Erik Zscheile
 * License: GPL-2+
 */
#pragma once
#include <netinet/in.h>

inline bool operator==(const in_addr &a, const in_addr &b) noexcept {
  return a.s_addr == b.s_addr;
}

inline bool operator!=(const in_addr &a, const in_addr &b) noexcept {
  return a.s_addr != b.s_addr;
}

inline uint32_t cidr_to_netmask(const uint8_t suffix) noexcept {
  return htonl(~(0xffffffff >> suffix));
}

// TODO: add needed function 'cidr6_to_netmask'
