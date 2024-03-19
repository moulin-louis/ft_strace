//
// Created by loumouli on 3/16/24.
//

#include "ft_strace.h"

static int parse_argp(const int key, char* arg, struct argp_state* state) {
  switch (key) {
  case 'c':
    stat_count = true;
    break;
  case 'v':
    fprintf(stderr, "Version 1.0, Louis MOULIN, loumouli\n");
    break;
  case ARGP_KEY_ARG:
    if (state->arg_num == 0)
      strcpy(state->input, arg);
    break;
  case ARGP_KEY_END:
    if (state->arg_num < 1)
      argp_usage(state);
    break;
  default: {
  }
  }
  return 0;
}

int32_t parse_opt(int ac, char** av, char path_exe[4096]) {
  const struct argp_option options[] = {
    {"count-stat", 'c', 0, 0,
     "Count time, calls, and errors for each system call and report a summary on program exit.", 0},
    {"version", 'v', 0, 0, "Print version info", 0},
    {0},
  };
  struct argp argp = {0};
  argp.options = options;
  argp.parser = parse_argp;
  argp.args_doc = "PROG [ARGS]";
  return argp_parse(&argp, ac, av, 0, 0, path_exe);
}

int32_t exec_arg(char** av, char** envp) {
  const int64_t pid = fork();
  if (pid == -1) {
    perror("parent: clone3");
    exit(1);
  }
  if (pid == 0) {
    raise(SIGSTOP);
    execve(get_path(av[1]), av + 1, envp);
    perror("execve");
    exit(1);
  }
  return pid;
}

void setup_tracer(const int64_t pid) {
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
