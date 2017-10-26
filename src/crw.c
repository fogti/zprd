/**
 * crw.c controlled read/write functions
 *
 * (C) 2010 Davide Brini.
 * (C) 2017 Erik Zscheile.
 *
 * License: GPL-3
 *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is
 * ugly, the algorithms are naive, error checking and input validation
 * are very basic, and of course there can be bugs. If that's not enough,
 * the program has not been thoroughly tested, so it might even fail at
 * the few simple things it should be supposed to do right.
 * Needless to say, I take no responsibility whatsoever for what the
 * program might do. The program has been written mostly for learning
 * purposes, and can be used in the hope that is useful, but everything
 * is to be taken "as is" and without any kind of warranty, implicit or
 * explicit. See the file LICENSE for further details.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "crw.h"

int tun_alloc(char *dev, const int flags) {
  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;

  if(*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

static int crw_end(const int cnt, const char * const action) {
  if(cnt >= 0) return cnt;
  perror(action);
  exit(1);
}

int cread(const int fd, char *buf, const int n) {
  return crw_end(
    read(fd, buf, n),
    "read()"
  );
}

int cwrite(const int fd, const char *buf, const int n) {
  return crw_end(
    write(fd, buf, n),
    "write()"
  );
}

int read_n(const int fd, char *buf, const int n) {
  int left = n;

  while(left > 0) {
    const int nread = cread(fd, buf, left);
    if(!nread) return 0;
    left -= nread;
    buf += nread;
  }
  return n;
}

// additional functions needed for work with UDP

int crecvfrom(const int fd, char *buf, const int n, struct sockaddr_in *addr) {
  socklen_t addrlen = sizeof(*addr);
  return crw_end(
    recvfrom(fd, buf, n, 0, (struct sockaddr *) addr, &addrlen),
    "recvfrom()"
  );
}

int csendto(const int fd, const char *buf, const int n, const struct sockaddr_in *addr) {
  return crw_end(
    sendto(fd, buf, n, 0, (struct sockaddr *) addr, sizeof(*addr)),
    "sendto()"
  );
}

int recv_n(const int fd, char *buf, const int n, struct sockaddr_in *addr) {
  int cnt;
  while(!(cnt = crecvfrom(fd, buf, n, addr))) ;
  return cnt;
}
