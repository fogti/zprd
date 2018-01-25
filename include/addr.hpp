#ifndef ADDR_HPP
# define ADDR_HPP 1
# include <netinet/in.h>

bool operator==(const in_addr &a, const in_addr &b) noexcept;
bool operator!=(const in_addr &a, const in_addr &b) noexcept;

uint32_t cidr_to_netmask(const uint8_t suffix) noexcept;
#endif
