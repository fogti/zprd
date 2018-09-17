/* based upon: https://stackoverflow.com/questions/77005/how-to-automatically-generate-a-stacktrace-when-my-program-crashes */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

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
  void *          array[50];
  void *          caller_address;
  char **         messages;
  int             size, i;
  sig_ucontext_t *uc = (sig_ucontext_t *)ucontext;

 /* Get the address at the time the signal was raised */
#if defined(__i386__) // gcc specific
  caller_address = (void *) uc->uc_mcontext.eip; // EIP: x86 specific
#elif defined(__x86_64__) // gcc specific
  caller_address = (void *) uc->uc_mcontext.rip; // RIP: x86_64 specific
#else
#error Unsupported architecture. // TODO: Add support for other arch.
#endif

  size = backtrace(array, 50);
  messages = backtrace_symbols(array, size);
}

int main(int argc, char ** argv) {
 struct sigaction sigact;
 sigact.sa_sigaction = crit_err_hdlr;
 sigact.sa_flags = SA_RESTART | SA_SIGINFO;
 sigaction(SIGSEGV, &sigact, (struct sigaction *)NULL);
}
