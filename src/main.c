//
// Created by loumouli on 3/14/24.
//

#include "ft_strace.h"

void exit_n_kill(const pid_t pid) {
  kill(pid, SIGKILL);
  exit(42);
}

int child_fn(char** av, char** envp) {
  kill(getpid(), SIGSTOP);
  if (execve(av[1], av + 1, envp) == -1) {
    perror("execve");
    exit(1);
  }
  exit(0);
}

void block_signal(pid_t pid, int* status) {
  sigset_t sig_new_mask;
  sigset_t sig_block;

  sigemptyset(&sig_new_mask);
  sigemptyset(&sig_block);
  sigprocmask(SIG_SETMASK, &sig_new_mask, NULL);
  waitpid(pid, status, 0);
  sigaddset(&sig_block, SIGHUP);
  sigaddset(&sig_block, SIGINT);
  sigaddset(&sig_block, SIGQUIT);
  sigaddset(&sig_block, SIGPIPE);
  sigaddset(&sig_block, SIGTERM);
  sigprocmask(SIG_BLOCK, &sig_block, NULL);
}

long clone3(struct clone_args* cl_args, const size_t size) { return syscall(SYS_clone3, cl_args, size); }

uint64_t check_syscall(pid_t pid, struct pt_regs* regs) {
  struct iovec iov = {regs, sizeof(struct pt_regs)};
  const int32_t syscall_status = ptrace(PT_SYSCALL, pid, NULL, NULL);
  if (syscall_status == -1) {
    perror("parent: ptrace(PTRACE_SYSCALL)");
    exit_n_kill(pid);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFEXITED(status))
    return -1;
  const int64_t retval = ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, (void*)&iov);
  if (retval == -1) {
    perror("parent: ptrace(PTRACE_GETREGSET)");
    exit_n_kill(pid);
  }
  return regs->orig_rax;
}

int main(int ac, char** av, char** envp) {
  if (ac == 1) {
    ft_putstr_fd("Usage: ./ft_strace COMMAND [COMMAND_OPTIONS]\n", 2);
    return 1;
  }
  __aligned_u64 x = 0;
  struct clone_args arg = {0};
  arg.flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;
  arg.child_tid = (__u64)&x;
  arg.exit_signal = SIGCHLD;
  const int64_t pid = clone3(&arg, sizeof(arg));
  if (pid == -1) {
    perror("parent: clone3");
    exit(1);
  }
  if (pid == 0)
    child_fn(av, envp);
  int64_t retval = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
  if (retval == -1) {
    perror("parent: ptrace(PTRACE_SEIZE)");
    exit_n_kill(pid);
  }
  int status = 0;
  block_signal(pid, &status);
  retval = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
  if (retval == -1) {
    perror("parent: ptrace(PTRACE_INTERRUPT)");
    exit_n_kill(pid);
  }
  while (true) {
    struct pt_regs regs_syscall;
    const uint64_t syscall_code = check_syscall(pid, &regs_syscall);
    if (retval == -1)
      break;
    struct pt_regs regs_retval;
    const uint64_t retval_syscall = check_syscall(pid, &regs_retval);
    dprintf(1, "syscall = %lu, exit code = %lu\n", syscall_code, retval_syscall);
  }
  kill(pid, SIGKILL);
  return 0;
}
