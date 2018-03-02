#ifndef ZPRD_MAIN_HPP
# define ZPRD_MAIN_HPP 1
# include <inttypes.h>
# include <stddef.h>
/** send_packet:
 * handles the sending of packets to a remote or local (identified by a)
 *
 * @param ent     the ip of the destination
 * @param buffer  the buffer
 * @param buflen  the length of the buffer
 * @ret           written bytes count
 **/
int send_packet(const uint32_t ent, const char *buffer, const size_t buflen) noexcept;

void set_ip_df(const uint8_t frag) noexcept;
#endif
