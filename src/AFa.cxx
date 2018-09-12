/**
 * AFa.cxx
 * This file is the main implementation of the 'generic address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#include "AFa.hpp"

#include <config.h>
#include <zprd_conf.hpp>

#include <stdio.h>
#include <arpa/inet.h>
#include <endian.h>
#include <string.h>

#ifdef USE_IPX
# include <netipx/ipx.h>
#endif

[[gnu::hot]]
size_t AFa_sa_family2size(const struct sockaddr_storage &sas) noexcept {
#define X_SASIZ(AFX,PROTO) case AF_##AFX: return sizeof(struct sockaddr_##PROTO);
  switch(sas.ss_family) {
    X_SASIZ(INET, in)
#ifdef USE_IPV6
    X_SASIZ(INET6, in6)
#endif
#ifdef USE_IPX
    X_SASIZ(IPX, ipx)
#endif
    default: return sizeof(struct sockaddr_storage);
  }
}

[[gnu::hot]]
int AFa_sa_compare(const struct sockaddr_storage &lhs, const struct sockaddr_storage &rhs) noexcept {
  size_t offset, cmpsiz;
  if(lhs.ss_family == rhs.ss_family) {
    offset = 0;
    cmpsiz = AFa_sa_family2size(lhs);
  } else {
    offset = offsetof(struct sockaddr_storage, ss_family);
    cmpsiz = sizeof(sa_family_t);
  }
  return memcmp(&lhs + offset, &rhs + offset, cmpsiz);
}

// sockaddr_* get pointer funcs

#define SA_XXX_PTR(PROTO,WHAT) (&reinterpret_cast<const struct sockaddr_##PROTO*>(&sas)->s##PROTO##_##WHAT)
#define X_CASE_X(AFX,PROTO,WHAT,TYPE) case AF_##AFX: return reinterpret_cast<const TYPE*>(SA_XXX_PTR(PROTO, WHAT));
#ifdef USE_IPV6
# define X_CASE_in6(WHAT,TYPE) X_CASE_X(INET6, in6, WHAT, TYPE)
#else
# define X_CASE_in6(WHAT,TYPE)
#endif
#ifdef USE_IPX
# define X_CASE_ipx(WHAT,TYPE) X_CASE_X(IPX, ipx, WHAT, TYPE)
#else
# define X_CASE_ipx(WHAT,TYPE)
#endif

#define GP_TEMPLATE(WHAT,TYPE) \
  const TYPE* AFa_gp_##WHAT(const struct sockaddr_storage &sas) noexcept { \
    switch(sas.ss_family) { \
      X_CASE_X(INET, in, WHAT, TYPE) \
      X_CASE_in6(WHAT, TYPE) \
      X_CASE_ipx(WHAT, TYPE) \
      default: return 0; \
    } \
  } \
  TYPE* AFa_gp_##WHAT(struct sockaddr_storage &sas) noexcept { \
    return const_cast<TYPE*>(AFa_gp_##WHAT(static_cast<const struct sockaddr_storage &>(sas))); \
  }

GP_TEMPLATE(addr, char)
GP_TEMPLATE(port, uint16_t)

#undef GP_TEMPLATE
#undef X_CASE_in6
#undef X_CASE_ipx

using std::string;

auto AFa_addr2string(const sa_family_t sa_fam, const char *addr) -> string {
  if(!addr) return "(null)";

  char buf[1058] = {0}; // the buffer should be large enough to hold any host addr + port number

  switch(sa_fam) {
    case AF_UNSPEC:
      return "localhost";
    case AF_INET:
#ifdef USE_IPV6
    case AF_INET6:
#endif
        ;
      inet_ntop(sa_fam, addr, buf, sizeof(buf));
      break;
/*
    case AF_IPX:
      snprintf(buf, sizeof(buf), "%s", ipx_ntoa(*addr));
      break;
 */
    default:
      return "-unsupported-AF-" + std::to_string(sa_fam);
  }

  return {buf};
}

auto AFa_port2string(const sa_family_t sa_fam, const uint16_t *sanport) -> string {
  return std::to_string(ntohs(*sanport));
}
