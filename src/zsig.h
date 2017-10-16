#ifndef ZSIG_H
# define ZSIG_H 1
# include <signal.h>
# ifdef __cplusplus
extern "C" {
# endif
  typedef void (*sighandler_t)(int);
  void my_signal(const int sig_nr, const sighandler_t sig_handler);
# ifdef __cplusplus
}
# endif
#endif
