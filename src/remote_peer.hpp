/**
 * remote_peer.hpp
 * This file contains parts of the oAFa 'outer address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <sys/socket.h> // sockaddr_storage
#include <netinet/in.h> // in_addr_t
#include <stddef.h>     // size_t
#include <time.h>       // time_t
#include <string>

struct remote_peer_t {
  sockaddr_storage saddr;

  remote_peer_t() noexcept;
  remote_peer_t(const sockaddr_storage &sas) noexcept;
  remote_peer_t(const remote_peer_t &o) noexcept = default;

  /* deprecated; construct sockaddr from IPv4 address */
  explicit remote_peer_t(const in_addr_t &x) noexcept;
  explicit remote_peer_t(const in_addr &x) noexcept;

  /* convert saddr to a string */
  auto addr2string() const -> std::string;
};

bool operator==(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;
bool operator!=(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;
bool operator< (const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;
bool operator> (const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;

struct remote_peer_detail_t : remote_peer_t {
  time_t seen;
  size_t cent; // config entry
  bool to_discard; // should this entry be deleted in the next cleanup round?

  explicit remote_peer_detail_t(const remote_peer_t &o) noexcept;
  explicit remote_peer_detail_t(const sockaddr_storage &sas) noexcept;
  remote_peer_detail_t(const remote_peer_detail_t &o) noexcept = default;
  remote_peer_detail_t(const remote_peer_t &o, const size_t cfgent) noexcept;

  const char *cfgent_name() const noexcept;
};
