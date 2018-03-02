#ifndef ADDR_HPP
# define ADDR_HPP 1
# include <netinet/in.h>

bool operator==(const in_addr &a, const in_addr &b) noexcept;

inline bool operator!=(const in_addr &a, const in_addr &b) noexcept {
  return !(a == b);
}

uint32_t cidr_to_netmask(const uint8_t suffix) noexcept;
#endif
