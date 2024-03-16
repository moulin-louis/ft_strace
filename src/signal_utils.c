//
// Created by loumouli on 3/16/24.
//

#include "ft_strace.h"

void signal_unblock(void) {
  sigset_t empty_mask;
  sigemptyset(&empty_mask);
  sigprocmask(SIG_SETMASK, &empty_mask, NULL);
}

void signal_block(void) {
  const int32_t sig_block[5] = {SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM};
  sigset_t block_mask;
  sigemptyset(&block_mask);
  for (uint64_t i = 0; i < 5; ++i)
    sigaddset(&block_mask, sig_block[i]);
  sigprocmask(SIG_BLOCK, &block_mask, NULL);
}

void handle_signal(const siginfo_t sig) { printf("SIG: si_code = %d, si_pid = %d ", sig.si_code, sig.si_pid); }
