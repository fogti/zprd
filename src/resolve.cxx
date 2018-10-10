/**
 * resolve.cxx
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#define __USE_MISC 1
#include "resolve.hpp"
#include <zs/ll/memut.hpp>
#include <config.h>
#include <stdio.h>  // printf
#include <netdb.h>  // getaddrinfo

bool resolve_hostname(std::string hostname, struct sockaddr_storage &remote, const sa_family_t preferred_af) noexcept {
  struct addrinfo hints, *servinfo;

  // setup hints
  zeroify(hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  {
    char * portptr = nullptr;
    const size_t befport = hostname.find('|');
    if(befport != std::string::npos && hostname[befport + 1]) {
      portptr = &hostname[befport];
      *(portptr++) = 0;
    }

    if(const int rv = getaddrinfo(hostname.c_str(), portptr, &hints, &servinfo)) {
      printf("CLIENT ERROR: getaddrinfo: %s\n", gai_strerror(rv));
      return false;
    }
  }

  struct addrinfo *siptr = servinfo;
  if(preferred_af != AF_UNSPEC) {
    for(; siptr; siptr = siptr->ai_next)
      if(siptr->ai_family == preferred_af)
        goto done;
    // if no possible entry matches the preferred address family, use first
    siptr = servinfo;
  }
  if(zs_unlikely(!siptr))
    return false;

 done:
  // copy ai_addr to remote + clear out unused rest
  partial_memcpy(&remote, reinterpret_cast<struct sockaddr_storage *>(siptr->ai_addr), siptr->ai_addrlen);
  freeaddrinfo(servinfo); // all done with this structure
  return true;
}
