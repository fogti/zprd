/**
 * resolve.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#pragma once
#include <sys/socket.h>

/** resolve_hostname:
 * resolves a hostname using (DNS) resolver and establishes a connection to it
 * TODO: support generic remote_peer_t, not only in_addr (IPv4)
 *
 * @param hostname  a host fqdn
 * @param remote    (in/out) the remote socket address
 * @ret             DNS ok marker
 **/
bool resolve_hostname(const char * const hostname, struct sockaddr_storage &remote, sa_family_t preferred_af) noexcept;
