/**
 * oAFa.cxx
 * This file is the main implementation of the 'generic address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#include "oAFa.hpp"
#include <config.h>

#include <netinet/in.h>
#include <string.h> // memcmp

#ifdef USE_IPX
# include <stdio.h>
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

#define SA_XXX_PTR(PROTO,WHAT) (&reinterpret_cast<struct sockaddr_##PROTO*>(&sas)->s##PROTO##_##WHAT)

bool AFa_sa2catchall(struct sockaddr_storage &sas) noexcept {
  switch(sas.ss_family) {
    case AF_INET:
      SA_XXX_PTR(in, addr)->s_addr = htonl(INADDR_ANY);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      *SA_XXX_PTR(in6, addr) = in6addr_any;
      break;
#endif
#ifdef USE_IPX
    case AF_IPX:
# warning "IPX is not supported in AFa_sa2catchall"
//    FIXME -- low importance
      //SA_XXX_PTR(ipx, addr) = ...IDK...;
      //break;
#endif
    default:
      return false;
  }
  return true;
}

// sockaddr_* get pointer funcs

#undef SA_XXX_PTR
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
