//
// Created by loumouli on 3/14/24.
//

#include "ft_strace.h"

t_syscall sc_table_64[SYSCALLS_NBR_64] = {SYSCALLS_ENT_64};
t_syscall sc_table_32[SYSCALLS_NBR_32] = {SYSCALLS_ENT_32};
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

void handle_syscall_io(const int32_t pid) {
  static bool syscall_status = false; // control if were dealing with the entry of a syscall or the exit
  t_regs regs = {0};
  struct iovec io = {
    .iov_base = &regs,
    .iov_len = sizeof(regs),
  };

  ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
  switch (io.iov_len) {
  case sizeof(regs.regs_64): { // Its a 64 bits process
    const uint64_t nbr = regs.regs_64.orig_rax;
    const t_syscall syscall = get_syscall_64(nbr);
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
  case sizeof(regs.regs_32): { // Its a 32 bits one
    const uint32_t nbr = regs.regs_32.orig_eax;
    const t_syscall syscall = get_syscall_32(nbr);
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
    fprintf(stderr, "REALY WEIRD SIZE OF REGISTER, ABORTING !!!\n");
    exit(1);
  }
}

int32_t analysis_tracee(const int64_t pid) {
  siginfo_t sig = {0};
  while (true) {
    int32_t status = 0;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
      ptrace(PTRACE_GETSIGINFO, pid, 0, &sig);
      int32_t signal = WSTOPSIG(status);
      if (sig.si_code == SIGTRAP || sig.si_code == (SIGTRAP | 0x80)) {
        handle_syscall_io(pid);
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
      exit(ret_value);
    }
    if (WIFSIGNALED(status)) {
      fprintf(stderr, "killed by sig\n");
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
  if (parse_opt(ac, av, path_exe))
    return 1;
  if (get_path(av[1]) == NULL) {
    fprintf(stderr, "ft_strace: %s: No such file\n", av[1]);
    return 1;
  }
  pid = exec_arg(av, envp);
  setup_tracer(pid);
  analysis_tracee(pid);
  signal_unblock();
  kill(pid, SIGKILL);
  return 0;
}
