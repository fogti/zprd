/**
 * resolve.cxx
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#define __USE_MISC 1
#include "resolve.hpp"
#include <stdio.h>  // printf
#include <string.h> // memset
#include <netdb.h>  // getaddrinfo

bool resolve_hostname(const char * const hostname, struct sockaddr_storage &remote, const sa_family_t preferred_af) noexcept {
  struct addrinfo hints, *servinfo;

  // setup hints
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if(const int rv = getaddrinfo(hostname, nullptr, &hints, &servinfo)) {
    printf("CLIENT ERROR: getaddrinfo: %s\n", gai_strerror(rv));
    return false;
  }

  struct addrinfo *siptr = servinfo;
  if(preferred_af != AF_UNSPEC) {
    for(; siptr; siptr = siptr->ai_next)
      if(siptr->ai_family == preferred_af)
        goto done;
    // if no possible entry matches the preferred address family, use first
    siptr = servinfo;
  }

 done:
  // copy ai_addr to remote + clear out unused rest
  memcpy(&remote, reinterpret_cast<struct sockaddr_storage *>(siptr->ai_addr), siptr->ai_addrlen);
  const size_t dif = sizeof(struct sockaddr_storage) - siptr->ai_addrlen;
  memset(&remote + siptr->ai_addrlen, 0, dif);
  freeaddrinfo(servinfo); // all done with this structure
  return true;
}
