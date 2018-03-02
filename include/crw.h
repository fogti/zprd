#ifndef CRW_H
# define CRW_H 1
# include <linux/if_tun.h>
# include <netinet/in.h>
# include <stddef.h>
# ifdef __cplusplus
extern "C" {
# endif
  int tun_alloc(char *dev, const int flags);
  int cread(const int fd, char *buf, const size_t n);
  int cwrite(const int fd, const char *buf, const size_t n);
  int crecvfrom(const int fd, char *buf, const size_t n, struct sockaddr_in *addr);
  int csendto(const int fd, const char *buf, const size_t n, const struct sockaddr_in *addr);
  int recv_n(const int fd, char *buf, const size_t n, struct sockaddr_in *addr);
# ifdef __cplusplus
}
# endif
#endif
