/**
 * backtrace.c
 * (C) 2018 Erik Zscheile.
 * License: dual licensed under MIT and GPL-2+
 * orig source: https://stackoverflow.com/questions/77005/how-to-automatically-generate-a-stacktrace-when-my-program-crashes
 **/

#include "backtrace.h"
#include <config.h>
#ifdef HAVE_WK_UCONTEXT_H
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
# ifndef __USE_GNU
#  define __USE_GNU
# endif

#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/ucontext.h>
#include <ucontext.h>
#include <unistd.h>

typedef struct ucontext sig_ucontext_t;

void crit_err_hdlr(int sig_num, siginfo_t * info, void * ucontext) {
 void *             array[50];
 void *             caller_address;
 char **            messages;
 int                size, i;
 sig_ucontext_t *   uc;

  uc = (sig_ucontext_t *)ucontext;

  /* Get the address at the time the signal was raised */
  /* gcc specific stuff follows */
#if defined(__i386__) // gcc specific
  caller_address = (void *) uc->uc_mcontext.eip; // EIP: x86 specific
#elif defined(__x86_64__) // gcc specific
  caller_address = (void *) uc->uc_mcontext.rip; // RIP: x86_64 specific
#else
# error Unsupported architecture. // TODO: Add support for other arch.
#endif

  fprintf(stderr, "signal %d (%s), address is %p from %p\n", sig_num,
   strsignal(sig_num), info->si_addr, (void *)caller_address);

  size = backtrace(array, 50);

  /* overwrite sigaction with caller's address */
  array[1] = caller_address;

  messages = backtrace_symbols(array, size);

  /* skip first stack frame (points here) */
  for (i = 1; i < size && messages != NULL; ++i)
    fprintf(stderr, "[bt]: (%d) %s\n", i, messages[i]);

  free(messages);

  exit(139);
}

void setup_sigsegv_handler(void) {
  struct sigaction sigact;

  sigact.sa_sigaction = crit_err_hdlr;
  sigact.sa_flags = SA_RESTART | SA_SIGINFO;

  if(sigaction(SIGSEGV, &sigact, (struct sigaction *)NULL) != 0) {
    fprintf(stderr, "error setting signal handler for %d (%s)\n",
      SIGSEGV, strsignal(SIGSEGV));
  }
}
#else /* !HAVE_WK_UCONTEXT_H */
void setup_sigsegv_handler(void) {
  // do nothing
}
#endif
