//
// Created by loumouli on 3/14/24.
//

#ifndef FT_STRACE_H
#define FT_STRACE_H


#include "libft.h"
#include "syscall_32.h"
#include "syscall_64.h"
#include "errno_table.h"


#include <argp.h> //needed for argp parser
#include <elf.h> //needed for NT_PRSTATUS macro in ptrace getregset
#include <sys/ptrace.h> //needed for ptrace
#define _GNU_SOURCE
#include <errno.h>
#include <sys/uio.h> //needed for iovec struct
#include <sys/wait.h> //needed for wait

typedef struct {
  char* name; // name of the syscall
  char* format; // printf like format for the argument of the syscall
} t_syscall;

typedef union {
  struct {
    long ebx;
    long ecx;
    long edx;
    long esi;
    long edi;
    long ebp;
    long eax;
    int xds;
    int xes;
    int xfs;
    int xgs;
    long orig_eax;
    long eip;
    int xcs;
    long eflags;
    long esp;
    int xss;
  } regs_32;
  struct {
    /*
     * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
     * unless syscall needs a complete, fully filled "struct pt_regs".
     */
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    /* These regs are callee-clobbered. Always saved on kernel entry. */
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    /*
     * On syscall entry, this is syscall#. On CPU exception, this is error code.
     * On hw interrupt, it's IRQ number:
     */
    unsigned long orig_rax;
    /* Return frame for iretq */
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
    /* top of stack page */
  } regs_64;
} t_regs;

extern t_syscall sc_table_64[SYSCALLS_NBR_64];
extern t_syscall sc_table_32[SYSCALLS_NBR_32];
extern pid_t pid;
extern bool stat_count;
extern char* errno_str[];

#define get_syscall_64(nbr) sc_table_64[nbr]
#define get_syscall_32(nbr) sc_table_32[nbr]
#define exit_n_kill(pid)                                                                                               \
  do {                                                                                                                 \
    kill(pid, SIGKILL);                                                                                                \
    exit(42);                                                                                                          \
  }                                                                                                                    \
  while (0)

// Setup function
void setup_tracer(int64_t pid);

int32_t parse_opt(int ac, char** av, char path_exe[4096]);

char* get_path(char* arg);

// Exec function
int32_t exec_arg(char** av, char** envp);

int child_fn(char** av, char** envp) __attribute__((noreturn));

// Signal function
void signal_unblock(void);

void signal_block(void);

void handle_signal(siginfo_t sig);


// Print function
void print_entry_sc_64(const t_syscall* syscall, t_regs* regs);

void print_exit_sc_64(const t_regs* regs);

void print_entry_sc_32(const t_syscall* syscall, t_regs* regs);

void print_exit_sc_32(const t_regs* regs);

// String manip function
void setup_string(const char* format, t_regs* regs);

#endif // FT_STRACE_H
