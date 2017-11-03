#ifndef ZPRD_MAIN_HPP
# define ZPRD_MAIN_HPP 1
# include <inttypes.h>
/** send_packet:
 * handles the sending of packets to a remote or local (identified by a)
 *
 * @param ent     the ip of the destination
 * @param buffer  the buffer
 * @param buflen  the length of the buffer
 * @ret           written bytes count
 **/
int send_packet(const uint32_t ent, const char *buffer, const int buflen);
#endif
