/** recentpkts.cxx loop detection using round-robin alike database of recent
 *                 packet ids
 * (C) 2017 - 2018 Erik Zscheile
 * License: GPL-3
 **/

#ifndef RECENTPKTS_HPP
# define RECENTPKTS_HPP 1
# include <inttypes.h>

/** RecentPkts_append:
 * append a packet to the recent packet database if its not already known
 * ages all packets
 * refreshs packet if already known
 * drops all expired packets
 *
 * @param ptr    pointer to packet
 * @param nbytes size of packet
 * @ret        is already known (true -> DUP!)
 **/
bool RecentPkts_append(const uint8_t *ptr, uint16_t nbytes);

#endif
