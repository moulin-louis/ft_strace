//
// Created by loumouli on 3/14/24.
//

#include "ft_strace.h"

int child_fn(void) {
  ft_putstr_fd("Im in child\n", 1);
  sigset_t set;
  int sig_recv = 0;

  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  printf("waiting for SIGUSR1\n");
  sigwait(&set, &sig_recv);
  printf("SIGUSR1 recv\n");
  for (uint64_t i = 0; i < 10; ++i) {
    printf("i = %lu\n", i);
  }
  exit(42);
}

long clone3(struct clone_args* cl_args, size_t size) { return syscall(SYS_clone3, cl_args, size); }

int main(int ac, char** av, char** env) {

  (void)ac;
  (void)av;
  (void)env;
  __aligned_u64 x = 0;
  struct clone_args arg = {
    CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID,
    0,
    (__u64)&x,
    0,
    SIGCHLD,
    0,
    0,
    0,
    0,
    0,
    0,
  };
  int64_t pid = clone3(&arg, sizeof(arg));

  if (pid == -1) {
    perror("clone3");
    exit(1);
  }
  if (pid == 0) {
    child_fn();
  }
  int64_t retval = ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT);
  if (retval == -1) {
    perror("ptrace(PTRACE_SEIZE)");
    exit(1);
  }
  retval = ptrace(PTRACE_INTERRUPT, pid, 0, 0);
  if (retval == -1) {
    perror("ptrace(PTRACE_INTERRUPT)");
    exit(1);
  }
  printf("Program seized and interrputed\n");
  printf("trying to active PTRACE_SYSCALL\n");
  retval = ptrace(PTRACE_SYSCALL, pid, 0, 0);
  if (retval == -1) {
    perror("ptrace(PTRACE_SYSCALL)");
    exit(1);
  }
  printf("Syscall activated for child!!!\n");
  kill(pid, SIGUSR1);
  char str[55];
  read(0, str, 55);
  return 0;
}
