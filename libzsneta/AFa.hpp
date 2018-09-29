/**
 * AFa.hpp
 * This file is the main header of the 'generic address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <sys/socket.h> // sa_family_t
#include <string>

auto AFa_addr2string(const sa_family_t sa_fam, const char *addr) -> std::string;
