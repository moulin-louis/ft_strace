//
// Created by loumouli on 3/19/24.
//

#include "ft_strace.h"

char strings[6][32] = {0};

void grab_string(uint64_t* address_tracee, uint64_t* address_tracer) {
  char path[4096] = {0};

  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  const int fd = open(path, O_RDONLY);
  if (fd == -1) {
    perror("open proc/[PID]/mem");
    exit(2);
  }
  lseek(fd, (__off_t)address_tracee, SEEK_SET);
  const int64_t retval = read(fd, address_tracer, 31);
  if (retval == -1) {
    perror("read");
    exit(2);
  }
  ((char*)address_tracer)[retval] = 0;
}

void setup_string(const char* format, t_regs* regs) {
  for (uint64_t idx = 2; idx < strlen(format); ++idx) {
    if (format[idx] != 's')
      continue;
    uint64_t* address_tracee;
    uint64_t* address_tracer;
    switch (idx / 2) {
    case 2:
      address_tracee = (uint64_t*)regs->regs_64.rdi;
      regs->regs_64.rdi = (uint64_t)strings[0];
      address_tracer = (uint64_t*)regs->regs_64.rdi;
      break;
    case 4:
      address_tracee = (uint64_t*)regs->regs_64.rsi;
      regs->regs_64.rsi = (uint64_t)strings[1];
      address_tracer = (uint64_t*)regs->regs_64.rsi;
      break;
    case 6:
      address_tracee = (uint64_t*)regs->regs_64.rdx;
      regs->regs_64.rdx = (uint64_t)strings[2];
      address_tracer = (uint64_t*)regs->regs_64.rdx;
      break;
    case 8:
      address_tracee = (uint64_t*)regs->regs_64.rcx;
      regs->regs_64.rcx = (uint64_t)strings[3];
      address_tracer = (uint64_t*)regs->regs_64.rcx;
      break;
    case 10:
      address_tracee = (uint64_t*)regs->regs_64.r8;
      regs->regs_64.r8 = (uint64_t)strings[4];
      address_tracer = (uint64_t*)regs->regs_64.r8;
      break;
    case 12:
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
