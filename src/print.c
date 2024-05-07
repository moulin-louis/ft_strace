//
// Created by loumouli on 3/19/24.
//

#include "ft_strace.h"

void print_entry_sc_64(const t_syscall* syscall, t_regs* regs) {
  const uint8_t str[4096] = {0};
  setup_string(syscall->format, regs);
  snprintf((char*)str, sizeof(str), syscall->format, syscall->name, regs->regs_64.rdi, regs->regs_64.rsi,
           regs->regs_64.rdx, regs->regs_64.rcx, regs->regs_64.r8, regs->regs_64.r9);
  for (uint64_t idx = 0; idx < strlen((char*)str); ++idx) {
    if (str[idx] == '\n') {
      fprintf(stderr, "\\n");
      continue;
    }
    fprintf(stderr, "%c", str[idx]);
  }
}

void print_exit_sc_64(const t_regs* regs) {
  const int64_t retval = regs->regs_64.rax;
  if (retval > -1 || retval < -4095) {
    if (retval > 10000 || retval < -10000)
      fprintf(stderr, ") = %#lx\n", retval);
    else
      fprintf(stderr, ") = %ld\n", retval);
  }
  else {
    if (-retval >= 512 && -retval <= 530)
      fprintf(stderr, ") = ? %ld\n", -retval);
    else
      fprintf(stderr, ") = -1 %s (%s)\n", errno_str[-retval], strerror(-retval));
  }
}

void print_entry_sc_32(const t_syscall* syscall, t_regs* regs) {
  char str[4096] = {0};
  setup_string(str, regs);
  snprintf(str, sizeof(str), syscall->format, syscall->name, regs->regs_32.ebx, regs->regs_32.ecx, regs->regs_32.edx,
           regs->regs_32.esi, regs->regs_32.edi, regs->regs_32.ebp);
  for (uint64_t idx = 0; idx < strlen(str); ++idx) {
    if (str[idx] == '\n') {
      printf("\\n");
      continue;
    }
    printf("%c", str[idx]);
  }
}

void print_exit_sc_32(const t_regs* regs) {
  const int32_t retval = (int32_t)regs->regs_32.eax;
  if (retval > -1 || retval < -4095) {
    if (retval > 10000 || retval < -10000)
      fprintf(stderr, ") = %#x\n", retval);
    fprintf(stderr, ") = %d\n", retval);
  }
  else {
    if (-retval >= 512 && -retval <= 530)
      fprintf(stderr, ") = ? %d\n", -retval);
    else
      fprintf(stderr, ") = -1 %d (%s)\n", -retval, strerror(-retval));
  }
}
