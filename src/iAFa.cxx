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

static iafa_at_t zs_attrib_pure sa_family2iafa_at(const sa_family_t sa_fam) noexcept {
  switch(sa_fam) {
    case AF_INET : return IAFA_AT_INET;
    case AF_IPX  : return IAFA_AT_IPX;
    case AF_INET6: return IAFA_AT_INET6;
    default:       return 0;
  }
}

static constexpr size_t zs_attrib_pure pli_at2alen(const iafa_at_t type) noexcept {
  return type & IAFA_AL_MAX;
}

inner_addr_t::inner_addr_t(const inner_addr_t &o) noexcept
  : type(o.type) {
  const size_t oalen = o.get_alen();
  memcpy(addr, o.addr, oalen);
  memset(addr + oalen, 0, sizeof(addr) - oalen);
}

inner_addr_t::inner_addr_t(const struct sockaddr_storage &o) noexcept {
  type = sa_family2iafa_at(o.ss_family);
  const size_t oalen = get_alen();
  memcpy(addr, AFa_gp_addr(o), oalen);
  memset(addr + oalen, 0, sizeof(addr) - oalen);
}

inner_addr_t::inner_addr_t(const uint32_t ip4a) noexcept : type(IAFA_AT_INET) {
  constexpr const size_t ipalen = sizeof(ip4a);
  static_assert(ipalen == pli_at2alen(IAFA_AT_INET));
  memcpy(addr, &ip4a, ipalen);
  memset(addr + ipalen, 0, sizeof(addr) - ipalen);
}

inner_addr_t::inner_addr_t(const in6_addr ip6a) noexcept : type(IAFA_AT_INET6) {
  constexpr const size_t ipalen = sizeof(ip6a);
  static_assert(ipalen == pli_at2alen(IAFA_AT_INET6));
  memcpy(addr, &ip6a, ipalen);
  memset(addr + ipalen, 0, sizeof(addr) - ipalen);
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

[[gnu::hot]]
static int compare_addr(const xner_addr_t &lhs, const xner_addr_t &rhs) noexcept {
  if(lhs.type != rhs.type)
    return memcmp(&lhs.type, &rhs.type, sizeof(iafa_at_t));
  const size_t alen = pli_at2alen(lhs.type);
  if(const int ret = memcmp(lhs.addr, rhs.addr, alen))
    return ret;
  return memcmp(lhs.nmsk, rhs.nmsk, alen);
}

bool operator==(const inner_addr_t &lhs, const inner_addr_t &rhs) noexcept
  { return !compare_addr(lhs, rhs); }
bool operator!=(const inner_addr_t &lhs, const inner_addr_t &rhs) noexcept
  { return compare_addr(lhs, rhs); }

bool operator==(const xner_addr_t &lhs, const xner_addr_t &rhs) noexcept
  { return !compare_addr(lhs, rhs); }
bool operator!=(const xner_addr_t &lhs, const xner_addr_t &rhs) noexcept
  { return compare_addr(lhs, rhs); }

xner_addr_t::xner_addr_t(const xner_addr_t &o) noexcept : inner_addr_t() {
  type = o.type;
  const size_t oalen = pli_at2alen(type), difl = sizeof(addr) - oalen;
  memcpy(addr, o.addr, oalen);
  memset(addr + oalen, 0, difl);
  memcpy(nmsk, o.nmsk, oalen);
  memset(nmsk + oalen, 0, difl);
}

xner_addr_t::xner_addr_t(const inner_addr_t &o, const size_t pflen) noexcept
  : inner_addr_t(o) { set_pflen(pflen); }

// source: https://github.com/nmav/ipcalc/blob/master/ipcalc.c : ipv6_prefix_to_mask
void xner_addr_t::set_pflen(const size_t pflen) noexcept {
  if(pflen > (sizeof(nmsk) * 8)) return;
  const size_t restbits = pflen % 8, fullbytes = pflen / 8;
  char *pos = nmsk;
  memset(pos, 0xff, fullbytes);
  pos += fullbytes;
  *pos = static_cast<unsigned long>(0xffU << (8 - restbits));
  memset(pos + 1, 0, sizeof(nmsk) - fullbytes - 1);
}

[[gnu::hot]]
void xner_apply_netmask(char * addr, const char * nmsk, const size_t cmplen) noexcept {
  for(size_t i = 0; i < cmplen; ++i)
    addr[i] &= nmsk[i];
}

#include <zs/ll/hash.hpp>

size_t inner_addr_hash::operator()(const inner_addr_t &addr) const noexcept {
  uintmax_t seed = 0;
  llzs::hash_combine(seed, addr.type);
  const char *aptr = &addr.addr[0], *aeptr = aptr + addr.get_alen();
  for(; aptr != aeptr; ++aptr)
    llzs::hash_combine(seed, *aptr);
  return seed;
}
