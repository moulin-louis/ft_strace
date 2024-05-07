//
// Created by loumouli on 3/14/24.
//

#include "ft_strace.h"

t_syscall sc_table_64[SYSCALLS_NBR_64] = {SYSCALLS_ENT_64};
t_syscall sc_table_32[SYSCALLS_NBR_32] = {SYSCALLS_ENT_32};
uint64_t registeredSyscall64[SYSCALLS_NBR_64] = {0};
uint64_t registeredSyscall32[SYSCALLS_NBR_32] = {0};
bool is64Process = false;
pid_t pid;
bool stat_count = false;
char* errno_str[] = {ERRNO_ENT};

bool execve_is_done(bool* syscall_status, const char* syscall_name) {
  static bool execve_is_done = false;
  if (syscall_status == NULL || syscall_name == NULL)
    return execve_is_done;
  if (execve_is_done == false && strcmp("execve", syscall_name) == 0) {
    execve_is_done = true;
    *syscall_status = true;
  }
  return execve_is_done;
}

void handle_syscall_io(void) {
  static bool syscall_status = false; // control if were dealing with the entry of a syscall or the exit
  t_regs regs = {0};
  struct iovec io = {
    .iov_base = &regs,
    .iov_len = sizeof(regs),
  };

  ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
  switch (io.iov_len) {
  case sizeof(regs.regs_64): { // It's a 64 bits process
    is64Process = true;
    const uint64_t nbr = regs.regs_64.orig_rax;
    const t_syscall syscall = get_syscall_64(nbr);
    if (stat_count)
      registeredSyscall64[nbr] += 1;
    if (execve_is_done(&syscall_status, syscall.name) == false) // tracee process has not yet fully started
      return;
    if (syscall_status) {
      print_entry_sc_64(&syscall, &regs);
      syscall_status = false;
    }
    else {
      print_exit_sc_64(&regs);
      syscall_status = true;
    }
    break;
  }
  case sizeof(regs.regs_32): { // It's a 32 bits one
    const uint32_t nbr = regs.regs_32.orig_eax;
    const t_syscall syscall = get_syscall_32(nbr);
    if (stat_count)
      registeredSyscall32[nbr] += 1;
    if (execve_is_done(&syscall_status, syscall.name) == false) // tracee process has not yet fully started
      return;
    if (syscall_status) {
      print_entry_sc_32(&syscall, &regs);
      syscall_status = false;
    }
    else {
      print_exit_sc_32(&regs);
      syscall_status = true;
    }
    break;
  }
  default:
    fprintf(stderr, "REALLY WEIRD SIZE OF REGISTER, ABORTING !!!\n");
    exit(1);
  }
}

void analysis_syscall(void) {
  if (is64Process) {
    for (uint64_t idx = 0; idx < SYSCALLS_NBR_64; ++idx) {
      if (registeredSyscall64[idx])
        printf("%s -> called %ld times\n", sc_table_64[idx].name, registeredSyscall64[idx]);
    }
    return;
  }
  for (uint64_t idx = 0; idx < SYSCALLS_NBR_32; ++idx) {
    if (registeredSyscall32[idx])
      printf("%s -> called %ld times\n", sc_table_32[idx].name, registeredSyscall32[idx]);
  }
}

int32_t analysis_tracee(void) {
  siginfo_t sig = {0};
  while (true) {
    int32_t status = 0;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
      ptrace(PTRACE_GETSIGINFO, pid, 0, &sig);
      int32_t signal = WSTOPSIG(status);
      if (sig.si_code == SIGTRAP || sig.si_code == (SIGTRAP | 0x80)) {
        handle_syscall_io();
        signal = 0;
      }
      else if (execve_is_done(NULL, NULL))
        handle_signal(sig);
      ptrace(PTRACE_SYSCALL, pid, 0, signal);
    }
    if (WIFEXITED(status)) {
      const char ret_value = WEXITSTATUS(status);
      fprintf(stderr, ") = ?\n");
      fprintf(stderr, "+++ exited with %d +++", ret_value);
      if (stat_count)
        analysis_syscall();
      exit(ret_value);
    }
    if (WIFSIGNALED(status)) {
      fprintf(stderr, "killed by sig\n");
      if (stat_count)
        analysis_syscall();
      raise(WTERMSIG(status));
      exit(128 + WTERMSIG(status));
    }
  }
}

int main(int ac, char** av, char** envp) {
  char path_exe[4096] = {0};
  if (ac == 1) {
    fprintf(stderr, "Usage: ft_strace [OPTION...] PROG [ARGS]\n");
    return 1;
  }
  const int offset = parse_opt(ac, av, path_exe);
  if (offset == -1)
    return 1;
  if (stat_count) {
    //redirect stderr to null so the output is clean with -c 
    const int fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
      perror("open /dev/null");
      return 1;
    }
    dup2(fd, STDERR_FILENO);
  }
  if (get_path(path_exe) == NULL) {
    fprintf(stderr, "ft_strace: %s: No such file\n", av[1]);
    return 1;
  }
  exec_arg(path_exe, offset, av, envp);
  setup_tracer();
  analysis_tracee();
  signal_unblock();
  return 0;
}
