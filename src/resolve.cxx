/**
 * resolve.cxx
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#define __USE_MISC 1
#include <stdio.h>
#include <string.h> // memset
#include <netdb.h> // getaddrinfo
#include "resolve.hpp"

bool resolve_hostname(const char * const hostname, struct in_addr &remote) noexcept {
  struct addrinfo hints, *servinfo;

  // setup hints
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  if(const int rv = getaddrinfo(hostname, nullptr, &hints, &servinfo)) {
    printf("CLIENT ERROR: getaddrinfo: %s\n", gai_strerror(rv));
    return false;
  }

  remote = reinterpret_cast<struct sockaddr_in *>(servinfo->ai_addr)->sin_addr;

  freeaddrinfo(servinfo); // all done with this structure
  return true;
}
