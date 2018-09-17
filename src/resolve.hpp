/**
 * resolve.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#pragma once
#include <sys/socket.h>
#include <string>

/** resolve_hostname:
 * resolves a hostname using (DNS) resolver and establishes a connection to it
 *
 * @param hostname  a host fqdn
 * @param remote    (in/out) the remote socket address
 * @ret             DNS ok marker
 **/
bool resolve_hostname(std::string hostname, struct sockaddr_storage &remote, sa_family_t preferred_af) noexcept;
