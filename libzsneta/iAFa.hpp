/**
 * iAFa.hpp
 * This file is the main header of the 'inner address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <config.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stddef.h>     // size_t
#include <string>

typedef uint16_t iafa_at_t;

// IAFA_AT_* -- address types
#define IAFA_AT_INET  0x0804
#define IAFA_AT_IPX   0x02ea
#define IAFA_AT_INET6 0x05b0

#define IAFA_TLEN     0x02
#define IAFA_AL_MAX   0x1f

zs_attrib_pure
sa_family_t iafa_at2sa_family(const iafa_at_t type) noexcept;

static inline constexpr size_t zs_attrib_pure pli_at2alen(const iafa_at_t type) noexcept {
  return type & IAFA_AL_MAX;
}

// POD for inner addresses
struct inner_addr_t {
  // type consists of two parts:
  //  first 2 bytes = type: ETH_P_* -alike spec, but (type & IAFA_AL_MAX) == get_alen()
  iafa_at_t type;

  // NOTE: addr is ALWAYS in network-byte-order, when inside this struct
  char addr[IAFA_AL_MAX];

  inner_addr_t() noexcept : type(0) { }
  inner_addr_t(const inner_addr_t &o) noexcept;
  inner_addr_t(const sockaddr_storage &o) noexcept;

  inner_addr_t& operator=(const inner_addr_t &o) noexcept;

  // convert from IPv4 address
  explicit inner_addr_t(const uint32_t ip4a) noexcept;

  // convert from IPv6 address
  explicit inner_addr_t(const in6_addr ip6a) noexcept;

  size_t get_alen() const noexcept;
  // tflen = actual needed length of type + char[get_alen()]
  size_t get_tflen() const noexcept;

  auto to_string() const -> std::string;

  // e.g. ipv4 addr == 255.255.255.255
  bool is_direct_broadcast() const noexcept;
};

// similar POD like inner_addr_t, but for local endpoint addrs + netmask
struct xner_addr_t final : inner_addr_t {
  char nmsk[IAFA_AL_MAX];

  xner_addr_t(const xner_addr_t &o) noexcept;
  xner_addr_t(const inner_addr_t &o, size_t pflen) noexcept;
  xner_addr_t(const sockaddr_storage &o, const sockaddr_storage &netmask) noexcept;

  xner_addr_t& operator=(const xner_addr_t &o) noexcept;
  void set_pflen(size_t pflen) noexcept;

 private:
  void i_set2am(const char * const __restrict__ p_addr, const char * const __restrict__ p_nmsk) noexcept;
};

bool operator==(const inner_addr_t &a, const inner_addr_t &b) noexcept;
bool operator!=(const inner_addr_t &a, const inner_addr_t &b) noexcept;
bool operator==(const xner_addr_t &a, const xner_addr_t &b) noexcept;
bool operator!=(const xner_addr_t &a, const xner_addr_t &b) noexcept;

// hash algorithm for unordered_map<inner_addr_t, ...>
struct inner_addr_hash {
  size_t operator()(const inner_addr_t &addr) const noexcept;
};

void xner_apply_netmask(char * addr, const char * nmsk, size_t cmplen = IAFA_AL_MAX) noexcept;
