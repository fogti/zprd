/**
 * iAFa.hpp
 * This file is the main header of the 'inner address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <config.h>
#include <sys/socket.h>
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

// POD for inner addresses
struct inner_addr_t final {
  // type consists of two parts:
  //  first 2 bytes = type: ETH_P_* -alike spec , but (type & IAFA_AL_MAX) == get_alen()
  iafa_at_t type;

  // NOTE: addr is ALWAYS in network-byte-order, when inside this struct
  char addr[IAFA_AL_MAX];

  inner_addr_t() noexcept : type(0) { }
  inner_addr_t(const inner_addr_t &o) noexcept;

  // convert from IPv4 address
  explicit inner_addr_t(const uint32_t ip4a) noexcept;

  size_t get_alen() const noexcept;
  // tflen = actual needed length of type + char[get_alen()]
  size_t get_tflen() const noexcept;

  auto to_string() const -> std::string;
};

bool operator==(const inner_addr_t &a, const inner_addr_t &b) noexcept;
bool operator!=(const inner_addr_t &a, const inner_addr_t &b) noexcept;

// hash algorithm for unordered_map<inner_addr_t, ...>
struct inner_addr_hash {
  size_t operator()(const inner_addr_t &addr) const noexcept;
};
