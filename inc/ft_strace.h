//
// Created by loumouli on 3/14/24.
//

#ifndef FT_STRACE_H
#define FT_STRACE_H

#include <sys/ptrace.h> //needed for ptrace
#include <asm/ptrace.h>
#include "libft.h"
#define _GNU_SOURCE
#include <sched.h> //needed for clone
#include <stdint.h> //needed for type like uint8_t/ uint64_t/etc
#include <sys/syscall.h>
#include <sys/wait.h>
#define _GNU_SOURCE
#include <elf.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

int child_fn(char** av, char** envp) __attribute__((noreturn));


#endif // FT_STRACE_H
