/**
 * iAFa.cxx
 * This file is the main source of the 'inner address family abstraction'
 * (payload-level / inner addresses)
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#include "iAFa.hpp"
#include "AFa.hpp"
#include <string.h>

using namespace std;

sa_family_t zs_attrib_pure iafa_at2sa_family(const iafa_at_t type) noexcept {
  switch(type) {
    case IAFA_AT_INET : return AF_INET;
    case IAFA_AT_IPX  : return AF_IPX;
    case IAFA_AT_INET6: return AF_INET6;
    default: return AF_UNSPEC;
  }
}

static constexpr size_t zs_attrib_pure pli_at2alen(const iafa_at_t type) noexcept {
  return type & IAFA_AL_MAX;
}

inner_addr_t::inner_addr_t(const uint32_t ip4a) noexcept : type(IAFA_AT_INET) {
  constexpr const size_t ip4alen = sizeof(ip4a);
  static_assert(ip4alen == pli_at2alen(IAFA_AT_INET));
  memcpy(addr, &ip4a, sizeof(ip4a));
  memset(addr + ip4alen, 0, sizeof(addr) - ip4alen);
}

size_t inner_addr_t::get_alen() const noexcept {
  return pli_at2alen(type);
}

size_t inner_addr_t::get_tflen() const noexcept {
  return sizeof(type) + pli_at2alen(type);
}

auto inner_addr_t::to_string() const -> string {
  return AFa_addr2string(iafa_at2sa_family(type), addr);
}

[[gnu::hot]]
static int compare_addr(const inner_addr_t &lhs, const inner_addr_t &rhs) noexcept {
  return (lhs.type == rhs.type)
    ? memcmp(lhs.addr, rhs.addr, pli_at2alen(lhs.type))
    : memcmp(&lhs.type, &rhs.type, sizeof(iafa_at_t));
}

bool operator==(const inner_addr_t &lhs, const inner_addr_t &rhs) noexcept
  { return !compare_addr(lhs, rhs); }
bool operator!=(const inner_addr_t &lhs, const inner_addr_t &rhs) noexcept
  { return compare_addr(lhs, rhs); }

#include <zs/ll/hash.hpp>

size_t inner_addr_hash::operator()(const inner_addr_t &addr) const noexcept {
  uintmax_t seed = 0;
  llzs::hash_combine(seed, addr.type);
  const char *aptr = &addr.addr[0], *aeptr = aptr + addr.get_alen();
  for(; aptr != aeptr; ++aptr)
    llzs::hash_combine(seed, *aptr);
  return seed;
}
