//
// Created by loumouli on 3/14/24.
//

#include "ft_strace.h"

t_syscall syscall_table[SYSCALLS_NBR_64] = {SYSCALLS_ENT_64};
bool stat_count = false;

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
  static bool syscall_status = false; // control if were dealing with the start of a syscall or the end
  struct pt_regs regs;
  struct iovec io = {
    .iov_base = &regs,
    .iov_len = sizeof(regs),
  };
  ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
  const uint64_t nbr = regs.orig_rax;
  const t_syscall syscall = get_syscall(nbr);
  if (!execve_is_done(&syscall_status, syscall.name))
    return;
  if (syscall_status) {
    printf("%s", syscall.name);
    syscall_status = false;
  }
  else {
    printf(" = %ld\n", regs.rax);
    syscall_status = true;
  }
}

int32_t analysis_tracee(const int64_t pid) {
  int32_t signal = 0;
  siginfo_t sig = {0};
  while (true) {
    int32_t status = 0;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
      ptrace(PTRACE_GETSIGINFO, pid, 0, &sig);
      signal = WSTOPSIG(status);
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
      printf(" = %d\n", ret_value);
      exit(ret_value);
    }
    if (WIFSIGNALED(status)) {
      printf("killed by sig\n");
      raise(WTERMSIG(status));
      exit(128 + WTERMSIG(status));
    }
  }
}

int main(int ac, char** av, char** envp) {
  (void)envp;
  char path_exe[4096] = {0};
  if (parse_arg(ac, av, path_exe)) {
    printf("parsing failed\n");
    return 1;
  }
  // const int64_t pid = exec_arg(av, envp);
  // setup_tracer(pid);
  // analysis_tracee(pid);
  // signal_unblock();
  // kill(pid, SIGKILL);
  return 0;
}
