#ifndef RESOLVE_HPP
# define RESOLVE_HPP 1
# include <netinet/in.h>

/** resolve_hostname:
 * resolves a hostname using (DNS) resolver and establishes a connection to it
 *
 * @param hostname  a host fqdn
 * @param remote    (in/out) the remote socket address
 * @ret             DNS ok marker
 **/
bool resolve_hostname(const char * const hostname, struct in_addr &remote);

#endif
