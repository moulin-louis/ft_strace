//
// Created by loumouli on 3/19/24.
//

#include "ft_strace.h"

char strings[6][32] = {0};

void grab_string(uint64_t* address_tracee, uint64_t* address_tracer) {
  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = address_tracer;
  local[0].iov_len = 31;
  remote[0].iov_base = address_tracee;
  remote[0].iov_len = 31;
  // next line is equivalent to `process_vm_readv(pid, local, 2, remote, 1, 0);` (we just don't use glibc
  // interface/wrapper)
  const ssize_t nread = syscall(310, pid, local, 2, remote, 1, 0);
  if (nread == -1) {
    perror("syscall 310 (process_readv)");
    exit(2);
  }
  ((char*)address_tracer)[nread] = 0;
}

void setup_string(const char* format, t_regs* regs) {
  uint64_t posArg = -1;
  for (uint64_t idx = 2; idx < strlen(format); ++idx) {
    if (format[idx] == '%') {
      posArg += 1;
      continue;
    }
    if (format[idx] != 's')
      continue;
    uint64_t* address_tracee;
    uint64_t* address_tracer;
    switch (posArg) {
    case 0:
      address_tracee = (uint64_t*)regs->regs_64.rdi;
      regs->regs_64.rdi = (uint64_t)strings[0];
      address_tracer = (uint64_t*)regs->regs_64.rdi;
      break;
    case 1:
      address_tracee = (uint64_t*)regs->regs_64.rsi;
      regs->regs_64.rsi = (uint64_t)strings[1];
      address_tracer = (uint64_t*)regs->regs_64.rsi;
      break;
    case 2:
      address_tracee = (uint64_t*)regs->regs_64.rdx;
      regs->regs_64.rdx = (uint64_t)strings[2];
      address_tracer = (uint64_t*)regs->regs_64.rdx;
      break;
    case 3:
      address_tracee = (uint64_t*)regs->regs_64.rcx;
      regs->regs_64.rcx = (uint64_t)strings[3];
      address_tracer = (uint64_t*)regs->regs_64.rcx;
      break;
    case 4:
      address_tracee = (uint64_t*)regs->regs_64.r8;
      regs->regs_64.r8 = (uint64_t)strings[4];
      address_tracer = (uint64_t*)regs->regs_64.r8;
      break;
    case 5:
      address_tracee = (uint64_t*)regs->regs_64.r9;
      regs->regs_64.r9 = (uint64_t)strings[5];
      address_tracer = (uint64_t*)regs->regs_64.r9;
      break;
    default:
      return;
    }
    grab_string(address_tracee, address_tracer);
  }
}
