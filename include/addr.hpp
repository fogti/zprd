#ifndef ADDR_HPP
# define ADDR_HPP 1
# include <netinet/in.h>

inline bool operator==(const in_addr &a, const in_addr &b) noexcept {
  return a.s_addr == b.s_addr;
}

inline bool operator!=(const in_addr &a, const in_addr &b) noexcept {
  return a.s_addr != b.s_addr;
}

inline uint32_t cidr_to_netmask(const uint8_t suffix) noexcept {
  return htonl(~(0xffffffff >> suffix));
}
#endif
