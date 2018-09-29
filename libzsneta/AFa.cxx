/**
 * AFa.cxx
 * This file is the main implementation of the 'generic address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#include "AFa.hpp"
#include "oAFa.hpp"
#include <config.h>
#include <arpa/inet.h>

#ifdef USE_IPX
# include <stdio.h>
# include <netipx/ipx.h>
#endif

using std::string;

static string ui162string(const uint16_t x) {
  return std::to_string(static_cast<unsigned>(x));
}

auto AFa_addr2string(const sa_family_t sa_fam, const char *addr) -> string {
  if(!addr) return "(null)";

  char buf[1058] = {0}; // the buffer should be large enough to hold any host addr + port number

  switch(sa_fam) {
    case AF_UNSPEC:
      return "localhost";
    case AF_INET:
    case AF_INET6:
      inet_ntop(sa_fam, addr, buf, sizeof(buf));
      break;
#ifdef USE_IPX
    case AF_IPX:
      snprintf(buf, sizeof(buf), "%s", ipx_ntoa(*addr));
      break;
#endif
    default:
      return "-unsupported-AF-" + ui162string(sa_fam);
  }

  return {buf};
}

[[gnu::hot]]
auto AFa_sa2string(const struct sockaddr_storage &sas, string &&prefix) noexcept -> string {
  if(!sas.ss_family) return "local";
  string ret = move(prefix);
  ret += AFa_addr2string(sas.ss_family, AFa_gp_addr(sas));
  ret += ':';
  const uint16_t * const sanport = AFa_gp_port(sas);
  ret += sanport ? ui162string(ntohs(*sanport)) : string("(null)");
  return ret;
}
