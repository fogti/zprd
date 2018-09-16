/**
 * AFa.hpp
 * This file is the main header of the 'generic address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <sys/socket.h>
#include <inttypes.h>
#include <stddef.h>     // size_t
#include <string>

// sockaddr_* sa_family funcs
size_t AFa_sa_family2size(const struct sockaddr_storage &sas) noexcept;
int AFa_sa_compare(const struct sockaddr_storage &lhs, const struct sockaddr_storage &rhs) noexcept;

// AFa_sa2catchall sets sas to the use-all-interfaces-catchall address
bool AFa_sa2catchall(struct sockaddr_storage &sas) noexcept;

// sockaddr_* get pointer funcs
const char    * AFa_gp_addr(const struct sockaddr_storage &sas) noexcept;
      char    * AFa_gp_addr(      struct sockaddr_storage &sas) noexcept;
const uint16_t* AFa_gp_port(const struct sockaddr_storage &sas) noexcept;
      uint16_t* AFa_gp_port(      struct sockaddr_storage &sas) noexcept;

// generic buffer based funcs
auto AFa_addr2string(const sa_family_t sa_fam, const char *addr) -> std::string;
auto AFa_port2string(const sa_family_t sa_fam, const uint16_t *sanport) -> std::string;
