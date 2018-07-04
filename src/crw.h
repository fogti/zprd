/**
 * crw.h
 * (C) 2018 Erik Zscheile.
 * License: GPL-3
 **/
#pragma once
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <stddef.h>
#include <cwa_noexcept.h>
#ifdef __cplusplus
extern "C" {
#endif
  int tun_alloc(char *dev, const int flags) noexcept;
  int cread(const int fd, char *buf, const size_t n) noexcept;
  int recv_n(const int fd, char *buf, const size_t n, struct sockaddr_in *addr) noexcept;
#ifdef __cplusplus
}
#endif
