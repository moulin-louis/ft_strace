//
// Created by loumouli on 3/14/24.
//

#ifndef FT_STRACE_H
#define FT_STRACE_H

#include <sys/ptrace.h> //needed for ptrace
#include "libft.h"
#define _GNU_SOURCE
#include <sched.h> //needed for clone
#include <stdint.h> //needed for type like uint8_t/ uint64_t/etc
#include <sys/syscall.h>
#include <sys/wait.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/sched.h>


#define __aligned_uint64_t uint64_t __attribute__((aligned(8)))

#endif // FT_STRACE_H
