//
// Created by loumouli on 3/14/24.
//

#ifndef FT_STRACE_H
#define FT_STRACE_H


#include "libft.h"
#include "syscall_64.h"

#include <argp.h>
#include <sys/ptrace.h> //needed for ptrace
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <elf.h>
#include <sys/uio.h>

typedef struct {
  char* name;
  char* format;
} t_syscall;

extern t_syscall syscall_table[SYSCALLS_NBR_64];
extern bool stat_count;

#define get_syscall(nbr) syscall_table[nbr]
#define exit_n_kill(pid) kill(pid, SIGKILL); exit(42);

int child_fn(char** av, char** envp) __attribute__((noreturn));

void signal_unblock(void);

void signal_block(void);

void handle_signal(siginfo_t sig);

void setup_tracer(int64_t pid);

int32_t parse_arg(int ac, char**av, char path_exe[4096]);

int32_t exec_arg(char** av, char** envp);
#endif // FT_STRACE_H
