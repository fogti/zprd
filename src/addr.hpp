#ifndef ADDR_HPP
# define ADDR_HPP 1
# include <netinet/in.h>

bool operator==(const in_addr &a, const in_addr &b);
bool operator!=(const in_addr &a, const in_addr &b);

// is_broadcast_addr: checks if the given addr is a broadcast address
bool is_broadcast_addr(const struct in_addr &a);
#endif
