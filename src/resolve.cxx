/**
 * resolve.cxx
 * (C) 2017 Erik Zscheile.
 * License: GPL-3
 **/

#define __USE_MISC 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include "resolve.hpp"

bool resolve_hostname(const char * const hostname, struct in_addr &remote) {
  struct addrinfo hints, *servinfo;

  // setup hints
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  if(const int rv = getaddrinfo(hostname, 0, &hints, &servinfo)) {
    printf("CLIENT ERROR: getaddrinfo: %s\n", gai_strerror(rv));
    return false;
  }

  remote = reinterpret_cast<struct sockaddr_in *>(servinfo->ai_addr)->sin_addr;

  freeaddrinfo(servinfo); // all done with this structure
  return true;
}
