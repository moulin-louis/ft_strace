//
// Created by loumouli on 3/16/24.
//

#include "ft_strace.h"

int32_t parse_opt(char** av, char path_exe[4096]) {
  if (strncmp(av[1], "-c", 2) == 0) {
    stat_count = true;
    memcpy(path_exe, av[2], strlen(av[2]));
    return 1;
  }
  memcpy(path_exe, av[1], strlen(av[1]));
  return 0;
}

void exec_arg(char* path_exe, int offset, char** av, char** envp) {
  pid = fork();
  if (pid == -1) {
    perror("parent: fork");
    exit(1);
  }
  if (pid == 0) {
    raise(SIGSTOP);
    execve(get_path(path_exe), av + offset + 1, envp);
    perror("execve");
    exit(1);
  }
}

void setup_tracer(void) {
  signal_unblock();
  signal_block();
  usleep(100);
  int64_t retval = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
  if (retval == -1) {
    perror("parent: ptrace(PTRACE_SEIZE)");
    exit_n_kill(pid);
  }
  retval = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
  if (retval == -1) {
    perror("parent: ptrace(PTRACE_INTERRUPT)");
    exit_n_kill(pid);
  }
  retval = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  if (retval == -1) {
    perror("parent: ptrace(PTRACE_SYSCALL)");
    exit_n_kill(pid);
  }
}
