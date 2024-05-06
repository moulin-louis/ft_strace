//
// Created by loumouli on 3/16/24.
//

// Copied from tsiguenz github

#ifndef SYSCALL_64_H
#define SYSCALL_64_H
#define SYSCALLS_NBR_64 441
#define SYSCALLS_ENT_64                                                                                                \
  [0] = {"read", "%s(%d, %p, %d"}, [1] = {"write", "%s(%d, \"%s\", %d"}, [2] = {"open", "%s(\"%s\", %d, %d"},          \
  [3] = {"close", "%s(%d"}, [4] = {"stat", "%s(\"%s\", %p"}, [5] = {"fstat", "%s(%d, %p"},                             \
  [6] = {"lstat", "%s(\"%s\", %p"}, [7] = {"poll", "%s(%p, %d, %d"}, [8] = {"lseek", "%s(%d, %d, %d"},                 \
  [9] = {"mmap", "%s(%p, %lu, %d, %d, %d, %d"}, [10] = {"mprotect", "%s(0x%lx, %d, 0x%lx"},                            \
  [11] = {"munmap", "%s(0x%lx, %d"}, [12] = {"brk", "%s(0x%lx"}, [13] = {"rt_sigaction", "%s(%d, %p, %p, %d"},         \
  [14] = {"rt_sigprocmask", "%s(%d, %p, %p, %d"}, [15] = {"rt_sigreturn", "%s(?, ?, ?, ?, ?, ?"},                      \
  [16] = {"ioctl", "%s(%d, %d, 0x%lx"}, [17] = {"pread64", "%s(%d, \"%s\", %d, %d"},                                   \
  [18] = {"pwrite64", "%s(%d, \"%s\", %d, %d"}, [19] = {"readv", "%s(0x%lx, %p, 0x%lx"},                               \
  [20] = {"writev", "%s(0x%lx, %p, 0x%lx"}, [21] = {"access", "%s(\"%s\", %d"}, [22] = {"pipe", "%s(%p"},              \
  [23] = {"select", "%s(%d, %p, %p, %p, %p"}, [24] = {"sched_yield", "%s("},                                           \
  [25] = {"mremap", "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx"}, [26] = {"msync", "%s(0x%lx, %d, %d"},                     \
  [27] = {"mincore", "%s(0x%lx, %d, \"%s\""}, [28] = {"madvise", "%s(0x%lx, %d, %d"},                                  \
  [29] = {"shmget", "%s(0x%lx, %d, %d"}, [30] = {"shmat", "%s(%d, \"%s\", %d"}, [31] = {"shmctl", "%s(%d, %d, %p"},    \
  [32] = {"dup", "%s(%d"}, [33] = {"dup2", "%s(%d, %d"}, [34] = {"pause", "%s("}, [35] = {"nanosleep", "%s(%p, %p"},   \
  [36] = {"getitimer", "%s(%d, %p"}, [37] = {"alarm", "%s(%d"}, [38] = {"setitimer", "%s(%d, %p, %p"},                 \
  [39] = {"getpid", "%s("}, [40] = {"sendfile", "%s(%d, %d, %p, %d"}, [41] = {"socket", "%s(%d, %d, %d"},              \
  [42] = {"connect", "%s(%d, %p, %d"}, [43] = {"accept", "%s(%d, %p, %p"},                                             \
  [44] = {"sendto", "%s(%d, %p, %d, 0x%lx, %p, %d"}, [45] = {"recvfrom", "%s(%d, %p, %d, 0x%lx, %p, %p"},              \
  [46] = {"sendmsg", "%s(%d, %p, 0x%lx"}, [47] = {"recvmsg", "%s(%d, %p, 0x%lx"}, [48] = {"shutdown", "%s(%d, %d"},    \
  [49] = {"bind", "%s(%d, %p, %d"}, [50] = {"listen", "%s(%d, %d"}, [51] = {"getsockname", "%s(%d, %p, %p"},           \
  [52] = {"getpeername", "%s(%d, %p, %p"}, [53] = {"socketpair", "%s(%d, %d, %d, %p"},                                 \
  [54] = {"setsockopt", "%s(%d, %d, %d, \"%s\", %d"}, [55] = {"getsockopt", "%s(%d, %d, %d, \"%s\", %p"},              \
  [56] = {"clone", "%s(0x%lx, 0x%lx, %p, %p, 0x%lx"}, [57] = {"fork", "%s("}, [58] = {"vfork", "%s("},                 \
  [59] = {"execve", "%s(\"%s\", %p, %p"}, [60] = {"exit", "%s(%d"}, [61] = {"wait4", "%s(%d, %p, %d, %p"},             \
  [62] = {"kill", "%s(%d, %d"}, [63] = {"uname", "%s(%p"}, [64] = {"semget", "%s(0x%lx, %d, %d"},                      \
  [65] = {"semop", "%s(%d, %p, 0x%lx"}, [66] = {"semctl", "%s(%d, %d, %d, 0x%lx"}, [67] = {"shmdt", "%s(\"%s\""},      \
  [68] = {"msgget", "%s(0x%lx, %d"}, [69] = {"msgsnd", "%s(%d, %p, %d, %d"},                                           \
  [70] = {"msgrcv", "%s(%d, %p, %d, 0x%lx, %d"}, [71] = {"msgctl", "%s(%d, %d, %p"},                                   \
  [72] = {"fcntl", "%s(%d, %d, 0x%lx"}, [73] = {"flock", "%s(%d, %d"}, [74] = {"fsync", "%s(%d"},                      \
  [75] = {"fdatasync", "%s(%d"}, [76] = {"truncate", "%s(\"%s\", 0x%lx"}, [77] = {"ftruncate", "%s(%d, 0x%lx"},        \
  [78] = {"getdents", "%s(%d, %p, %d"}, [79] = {"getcwd", "%s(\"%s\", 0x%lx"}, [80] = {"chdir", "%s(\"%s\""},          \
  [81] = {"fchdir", "%s(%d"}, [82] = {"rename", "%s(\"%s\", \"%s\""}, [83] = {"mkdir", "%s(\"%s\", %d"},               \
  [84] = {"rmdir", "%s(\"%s\""}, [85] = {"creat", "%s(\"%s\", %d"}, [86] = {"link", "%s(\"%s\", \"%s\""},              \
  [87] = {"unlink", "%s(\"%s\""}, [88] = {"symlink", "%s(\"%s\", \"%s\""},                                             \
  [89] = {"readlink", "%s(\"%s\", \"%s\", %d"}, [90] = {"chmod", "%s(\"%s\", %d"}, [91] = {"fchmod", "%s(%d, %d"},     \
  [92] = {"chown", "%s(\"%s\", %d, %d"}, [93] = {"fchown", "%s(%d, %d, %d"}, [94] = {"lchown", "%s(\"%s\", %d, %d"},   \
  [95] = {"umask", "%s(%d"}, [96] = {"gettimeofday", "%s(%p, %p"}, [97] = {"getrlimit", "%s(%d, %p"},                  \
  [98] = {"getrusage", "%s(%d, %p"}, [99] = {"sysinfo", "%s(%p"}, [100] = {"times", "%s(%p"},                          \
  [101] = {"ptrace", "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx"}, [102] = {"getuid", "%s("},                                      \
  [103] = {"syslog", "%s(%d, \"%s\", %d"}, [104] = {"getgid", "%s("}, [105] = {"setuid", "%s(%d"},                     \
  [106] = {"setgid", "%s(%d"}, [107] = {"geteuid", "%s("}, [108] = {"getegid", "%s("},                                 \
  [109] = {"setpgid", "%s(%d, %d"}, [110] = {"getppid", "%s("}, [111] = {"getpgrp", "%s("}, [112] = {"setsid", "%s("}, \
  [113] = {"setreuid", "%s(%d, %d"}, [114] = {"setregid", "%s(%d, %d"}, [115] = {"getgroups", "%s(%d, %p"},            \
  [116] = {"setgroups", "%s(%d, %p"}, [117] = {"setresuid", "%s(%d, %d, %d"}, [118] = {"getresuid", "%s(%p, %p, %p"},  \
  [119] = {"setresgid", "%s(%d, %d, %d"}, [120] = {"getresgid", "%s(%p, %p, %p"}, [121] = {"getpgid", "%s(%d"},        \
  [122] = {"setfsuid", "%s(%d"}, [123] = {"setfsgid", "%s(%d"}, [124] = {"getsid", "%s(%d"},                           \
  [125] = {"capget", "%s(0x%lx, 0x%lx"}, [126] = {"capset", "%s(0x%lx, 0x%lx"},                                        \
  [127] = {"rt_sigpending", "%s(%p, %d"}, [128] = {"rt_sigtimedwait", "%s(%p, %p, %p, %d"},                            \
  [129] = {"rt_sigqueueinfo", "%s(%d, %d, %p"}, [130] = {"rt_sigsuspend", "%s(%p, %d"},                                \
  [131] = {"sigaltstack", "%s(%p, %p"}, [132] = {"utime", "%s(\"%s\", %p"}, [133] = {"mknod", "%s(\"%s\", %d, 0x%lx"}, \
  [134] = {"uselib", "%s(\"%s\""}, [135] = {"personality", "%s(%d"}, [136] = {"ustat", "%s(0x%lx, %p"},                \
  [137] = {"statfs", "%s(\"%s\", %p"}, [138] = {"fstatfs", "%s(%d, %p"}, [139] = {"sysfs", "%s(%d, 0x%lx, 0x%lx"},     \
  [140] = {"getpriority", "%s(%d, %d"}, [141] = {"setpriority", "%s(%d, %d, %d"},                                      \
  [142] = {"sched_setparam", "%s(%d, %p"}, [143] = {"sched_getparam", "%s(%d, %p"},                                    \
  [144] = {"sched_setscheduler", "%s(%d, %d, %p"}, [145] = {"sched_getscheduler", "%s(%d"},                            \
  [146] = {"sched_get_priority_max", "%s(%d"}, [147] = {"sched_get_priority_min", "%s(%d"},                            \
  [148] = {"sched_rr_get_interval", "%s(%d, %p"}, [149] = {"mlock", "%s(0x%lx, %d"},                                   \
  [150] = {"munlock", "%s(0x%lx, %d"}, [151] = {"mlockall", "%s(%d"}, [152] = {"munlockall", "%s("},                   \
  [153] = {"vhangup", "%s("}, [154] = {"modify_ldt", "%s(?, ?, ?, ?, ?, ?"},                                           \
  [155] = {"pivot_root", "%s(\"%s\", \"%s\""}, [156] = {"_sysctl", "%s(?, ?, ?, ?, ?, ?"},                             \
  [157] = {"prctl", "%s(%d, 0x%lx, 0x%lx, 0x%lx, 0x%lx"}, [158] = {"arch_prctl", "%s(%d, %p"},                         \
  [159] = {"adjtimex", "%s(%p"}, [160] = {"setrlimit", "%s(%d, %p"}, [161] = {"chroot", "%s(\"%s\""},                  \
  [162] = {"sync", "%s("}, [163] = {"acct", "%s(\"%s\""}, [164] = {"settimeofday", "%s(%p, %p"},                       \
  [165] = {"mount", "%s(\"%s\", \"%s\", \"%s\", 0x%lx, %p"}, [166] = {"umount2", "%s(?, ?, ?, ?, ?, ?"},               \
  [167] = {"swapon", "%s(\"%s\", %d"}, [168] = {"swapoff", "%s(\"%s\""}, [169] = {"reboot", "%s(%d, %d, %d, %p"},      \
  [170] = {"sethostname", "%s(\"%s\", %d"}, [171] = {"setdomainname", "%s(\"%s\", %d"},                                \
  [172] = {"iopl", "%s(?, ?, ?, ?, ?, ?"}, [173] = {"ioperm", "%s(0x%lx, 0x%lx, %d"},                                  \
  [174] = {"create_module", "%s(?, ?, ?, ?, ?, ?"}, [175] = {"init_module", "%s(%p, 0x%lx, \"%s\""},                   \
  [176] = {"delete_module", "%s(\"%s\", %d"}, [177] = {"get_kernel_syms", "%s(?, ?, ?, ?, ?, ?"},                      \
  [178] = {"query_module", "%s(?, ?, ?, ?, ?, ?"}, [179] = {"quotactl", "%s(%d, \"%s\", 0x%lx, %p"},                   \
  [180] = {"nfsservctl", "%s(?, ?, ?, ?, ?, ?"}, [181] = {"getpmsg", "%s(?, ?, ?, ?, ?, ?"},                           \
  [182] = {"putpmsg", "%s(?, ?, ?, ?, ?, ?"}, [183] = {"afs_syscall", "%s(?, ?, ?, ?, ?, ?"},                          \
  [184] = {"tuxcall", "%s(?, ?, ?, ?, ?, ?"}, [185] = {"security", "%s(?, ?, ?, ?, ?, ?"}, [186] = {"gettid", "%s("},  \
  [187] = {"readahead", "%s(%d, %d, %d"}, [188] = {"setxattr", "%s(\"%s\", \"%s\", %p, %d, %d"},                       \
  [189] = {"lsetxattr", "%s(\"%s\", \"%s\", %p, %d, %d"}, [190] = {"fsetxattr", "%s(%d, \"%s\", %p, %d, %d"},          \
  [191] = {"getxattr", "%s(\"%s\", \"%s\", %p, %d"}, [192] = {"lgetxattr", "%s(\"%s\", \"%s\", %p, %d"},               \
  [193] = {"fgetxattr", "%s(%d, \"%s\", %p, %d"}, [194] = {"listxattr", "%s(\"%s\", \"%s\", %d"},                      \
  [195] = {"llistxattr", "%s(\"%s\", \"%s\", %d"}, [196] = {"flistxattr", "%s(%d, \"%s\", %d"},                        \
  [197] = {"removexattr", "%s(\"%s\", \"%s\""}, [198] = {"lremovexattr", "%s(\"%s\", \"%s\""},                         \
  [199] = {"fremovexattr", "%s(%d, \"%s\""}, [200] = {"tkill", "%s(%d, %d"}, [201] = {"time", "%s(%p"},                \
  [202] = {"futex", "%s(%p, %d, 0x%lx, %p, %p, 0x%lx"}, [203] = {"sched_setaffinity", "%s(%d, %d, %p"},                \
  [204] = {"sched_getaffinity", "%s(%d, %d, %p"}, [205] = {"set_thread_area", "%s(?, ?, ?, ?, ?, ?"},                  \
  [206] = {"io_setup", "%s(0x%lx, %p"}, [207] = {"io_destroy", "%s(0x%lx"},                                            \
  [208] = {"io_getevents", "%s(0x%lx, 0x%lx, 0x%lx, %p, %p"}, [209] = {"io_submit", "%s(0x%lx, 0x%lx, %p"},            \
  [210] = {"io_cancel", "%s(0x%lx, %p, %p"}, [211] = {"get_thread_area", "%s(?, ?, ?, ?, ?, ?"},                       \
  [212] = {"lookup_dcookie", "%s(0x%lx, \"%s\", %d"}, [213] = {"epoll_create", "%s(%d"},                               \
  [214] = {"epoll_ctl_old", "%s(?, ?, ?, ?, ?, ?"}, [215] = {"epoll_wait_old", "%s(?, ?, ?, ?, ?, ?"},                 \
  [216] = {"remap_file_pages", "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx"}, [217] = {"getdents64", "%s(%d, %p, %d"},       \
  [218] = {"set_tid_address", "%s(%p"}, [219] = {"restart_syscall", "%s("},                                            \
  [220] = {"semtimedop", "%s(%d, %p, 0x%lx, %p"}, [221] = {"fadvise64", "%s(%d, %d, %d, %d"},                          \
  [222] = {"timer_create", "%s(0x%lx, %p, %p"}, [223] = {"timer_settime", "%s(0x%lx, %d, %p, %p"},                     \
  [224] = {"timer_gettime", "%s(0x%lx, %p"}, [225] = {"timer_getoverrun", "%s(0x%lx"},                                 \
  [226] = {"timer_delete", "%s(0x%lx"}, [227] = {"clock_settime", "%s(0x%lx, %p"},                                     \
  [228] = {"clock_gettime", "%s(0x%lx, %p"}, [229] = {"clock_getres", "%s(0x%lx, %p"},                                 \
  [230] = {"clock_nanosleep", "%s(0x%lx, %d, %p, %p"}, [231] = {"exit_group", "%s(%d"},                                \
  [232] = {"epoll_wait", "%s(%d, %p, %d, %d"}, [233] = {"epoll_ctl", "%s(%d, %d, %d, %p"},                             \
  [234] = {"tgkill", "%s(%d, %d, %d"}, [235] = {"utimes", "%s(\"%s\", %p"},                                            \
  [236] = {"vserver", "%s(?, ?, ?, ?, ?, ?"}, [237] = {"mbind", "%s(0x%lx, 0x%lx, 0x%lx, %p, 0x%lx, 0x%lx"},           \
  [238] = {"set_mempolicy", "%s(%d, %p, 0x%lx"}, [239] = {"get_mempolicy", "%s(%p, %p, 0x%lx, 0x%lx, 0x%lx"},          \
  [240] = {"mq_open", "%s(\"%s\", %d, %d, %p"}, [241] = {"mq_unlink", "%s(\"%s\""},                                    \
  [242] = {"mq_timedsend", "%s(0x%lx, \"%s\", %d, %d, %p"},                                                            \
  [243] = {"mq_timedreceive", "%s(0x%lx, \"%s\", %d, %p, %p"}, [244] = {"mq_notify", "%s(0x%lx, %p"},                  \
  [245] = {"mq_getsetattr", "%s(0x%lx, %p, %p"}, [246] = {"kexec_load", "%s(0x%lx, 0x%lx, %p, 0x%lx"},                 \
  [247] = {"waitid", "%s(%d, %d, %p, %d, %p"}, [248] = {"add_key", "%s(\"%s\", \"%s\", %p, %d, 0x%lx"},                \
  [249] = {"request_key", "%s(\"%s\", \"%s\", \"%s\", 0x%lx"},                                                         \
  [250] = {"keyctl", "%s(%d, 0x%lx, 0x%lx, 0x%lx, 0x%lx"}, [251] = {"ioprio_set", "%s(%d, %d, %d"},                    \
  [252] = {"ioprio_get", "%s(%d, %d"}, [253] = {"inotify_init", "%s("},                                                \
  [254] = {"inotify_add_watch", "%s(%d, \"%s\", 0x%lx"}, [255] = {"inotify_rm_watch", "%s(%d, 0x%lx"},                 \
  [256] = {"migrate_pages", "%s(%d, 0x%lx, %p, %p"}, [257] = {"openat", "%s(%d, \"%s\", %d, %d"},                      \
  [258] = {"mkdirat", "%s(%d, \"%s\", %d"}, [259] = {"mknodat", "%s(%d, \"%s\", %d, 0x%lx"},                           \
  [260] = {"fchownat", "%s(%d, \"%s\", %d, %d, %d"}, [261] = {"futimesat", "%s(%d, \"%s\", %p"},                       \
  [262] = {"newfstatat", "%s(%d, \"%s\", %p, %d"}, [263] = {"unlinkat", "%s(%d, \"%s\", %d"},                          \
  [264] = {"renameat", "%s(%d, \"%s\", %d, \"%s\""}, [265] = {"linkat", "%s(%d, \"%s\", %d, \"%s\", %d"},              \
  [266] = {"symlinkat", "%s(\"%s\", %d, \"%s\""}, [267] = {"readlinkat", "%s(%d, \"%s\", \"%s\", %d"},                 \
  [268] = {"fchmodat", "%s(%d, \"%s\", %d"}, [269] = {"faccessat", "%s(%d, \"%s\", %d"},                               \
  [270] = {"pselect6", "%s(%d, %p, %p, %p, %p, %p"}, [271] = {"ppoll", "%s(%p, %d, %p, %p, %d"},                       \
  [272] = {"unshare", "%s(0x%lx"}, [273] = {"set_robust_list", "%s(%p, %d"},                                           \
  [274] = {"get_robust_list", "%s(%d, %p, %p"}, [275] = {"splice", "%s(%d, %p, %d, %p, %d, %d"},                       \
  [276] = {"tee", "%s(%d, %d, %d, %d"}, [277] = {"sync_file_range", "%s(%d, %d, %d, %d"},                              \
  [278] = {"vmsplice", "%s(%d, %p, 0x%lx, %d"}, [279] = {"move_pages", "%s(%d, 0x%lx, %p, %p, %p, %d"},                \
  [280] = {"utimensat", "%s(%d, \"%s\", %p, %d"}, [281] = {"epoll_pwait", "%s(%d, %p, %d, %d, %p, %d"},                \
  [282] = {"signalfd", "%s(%d, %p, %d"}, [283] = {"timerfd_create", "%s(%d, %d"}, [284] = {"eventfd", "%s(%d"},        \
  [285] = {"fallocate", "%s(%d, %d, %d, %d"}, [286] = {"timerfd_settime", "%s(%d, %d, %p, %p"},                        \
  [287] = {"timerfd_gettime", "%s(%d, %p"}, [288] = {"accept4", "%s(%d, %p, %p, %d"},                                  \
  [289] = {"signalfd4", "%s(%d, %p, %d, %d"}, [290] = {"eventfd2", "%s(%d, %d"}, [291] = {"epoll_create1", "%s(%d"},   \
  [292] = {"dup3", "%s(%d, %d, %d"}, [293] = {"pipe2", "%s(%p, %d"}, [294] = {"inotify_init1", "%s(%d"},               \
  [295] = {"preadv", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx"}, [296] = {"pwritev", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx"},   \
  [297] = {"rt_tgsigqueueinfo", "%s(%d, %d, %d, %p"}, [298] = {"perf_event_open", "%s(%p, %d, %d, %d, 0x%lx"},         \
  [299] = {"recvmmsg", "%s(%d, %p, %d, 0x%lx, %p"}, [300] = {"fanotify_init", "%s(%d, %d"},                            \
  [301] = {"fanotify_mark", "%s(%d, %d, 0x%lx, %d, \"%s\""}, [302] = {"prlimit64", "%s(%d, %d, %p, %p"},               \
  [303] = {"name_to_handle_at", "%s(%d, \"%s\", %p, %p, %d"}, [304] = {"open_by_handle_at", "%s(%d, %p, %d"},          \
  [305] = {"clock_adjtime", "%s(0x%lx, %p"}, [306] = {"syncfs", "%s(%d"},                                              \
  [307] = {"sendmmsg", "%s(%d, %p, %d, 0x%lx"}, [308] = {"setns", "%s(%d, %d"}, [309] = {"getcpu", "%s(%p, %p, %p"},   \
  [310] = {"process_vm_readv", "%s(%d, %p, 0x%lx, %p, 0x%lx, 0x%lx"},                                                  \
  [311] = {"process_vm_writev", "%s(%d, %p, 0x%lx, %p, 0x%lx, 0x%lx"},                                                 \
  [312] = {"kcmp", "%s(%d, %d, %d, 0x%lx, 0x%lx"}, [313] = {"finit_module", "%s(%d, \"%s\", %d"},                      \
  [314] = {"sched_setattr", "%s(%d, %p, %d"}, [315] = {"sched_getattr", "%s(%d, %p, %d, %d"},                          \
  [316] = {"renameat2", "%s(%d, \"%s\", %d, \"%s\", %d"}, [317] = {"seccomp", "%s(%d, %d, %p"},                        \
  [318] = {"getrandom", "%s(\"%s\", %d, %d"}, [319] = {"memfd_create", "%s(\"%s\", %d"},                               \
  [320] = {"kexec_file_load", "%s(%d, %d, 0x%lx, \"%s\", 0x%lx"}, [321] = {"bpf", "%s(%d, %p, %d"},                    \
  [322] = {"execveat", "%s(%d, \"%s\", %p, %p, %d"}, [323] = {"userfaultfd", "%s(%d"},                                 \
  [324] = {"membarrier", "%s(%d, %d"}, [325] = {"mlock2", "%s(0x%lx, %d, %d"},                                         \
  [326] = {"copy_file_range", "%s(%d, %p, %d, %p, %d, %d"},                                                            \
  [327] = {"preadv2", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx, %d"},                                                        \
  [328] = {"pwritev2", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx, %d"}, [329] = {"pkey_mprotect", "%s(0x%lx, %d, 0x%lx, %d"}, \
  [330] = {"pkey_alloc", "%s(0x%lx, 0x%lx"}, [331] = {"pkey_free", "%s(%d"},                                           \
  [332] = {"statx", "%s(%d, \"%s\", 0x%lx, 0x%lx, %p"}, [333] = {"io_pgetevents", "%s("}, [334] = {"rseq", "%s("},     \
  [335] = {"not implemented", "%s("}, [336] = {"not implemented", "%s("}, [337] = {"not implemented", "%s("},          \
  [338] = {"not implemented", "%s("}, [339] = {"not implemented", "%s("}, [340] = {"not implemented", "%s("},          \
  [341] = {"not implemented", "%s("}, [342] = {"not implemented", "%s("}, [343] = {"not implemented", "%s("},          \
  [344] = {"not implemented", "%s("}, [345] = {"not implemented", "%s("}, [346] = {"not implemented", "%s("},          \
  [347] = {"not implemented", "%s("}, [348] = {"not implemented", "%s("}, [349] = {"not implemented", "%s("},          \
  [350] = {"not implemented", "%s("}, [351] = {"not implemented", "%s("}, [352] = {"not implemented", "%s("},          \
  [353] = {"not implemented", "%s("}, [354] = {"not implemented", "%s("}, [355] = {"not implemented", "%s("},          \
  [356] = {"not implemented", "%s("}, [357] = {"not implemented", "%s("}, [358] = {"not implemented", "%s("},          \
  [359] = {"not implemented", "%s("}, [360] = {"not implemented", "%s("}, [361] = {"not implemented", "%s("},          \
  [362] = {"not implemented", "%s("}, [363] = {"not implemented", "%s("}, [364] = {"not implemented", "%s("},          \
  [365] = {"not implemented", "%s("}, [366] = {"not implemented", "%s("}, [367] = {"not implemented", "%s("},          \
  [368] = {"not implemented", "%s("}, [369] = {"not implemented", "%s("}, [370] = {"not implemented", "%s("},          \
  [371] = {"not implemented", "%s("}, [372] = {"not implemented", "%s("}, [373] = {"not implemented", "%s("},          \
  [374] = {"not implemented", "%s("}, [375] = {"not implemented", "%s("}, [376] = {"not implemented", "%s("},          \
  [377] = {"not implemented", "%s("}, [378] = {"not implemented", "%s("}, [379] = {"not implemented", "%s("},          \
  [380] = {"not implemented", "%s("}, [381] = {"not implemented", "%s("}, [382] = {"not implemented", "%s("},          \
  [383] = {"not implemented", "%s("}, [384] = {"not implemented", "%s("}, [385] = {"not implemented", "%s("},          \
  [386] = {"not implemented", "%s("}, [387] = {"not implemented", "%s("}, [388] = {"not implemented", "%s("},          \
  [389] = {"not implemented", "%s("}, [390] = {"not implemented", "%s("}, [391] = {"not implemented", "%s("},          \
  [392] = {"not implemented", "%s("}, [393] = {"not implemented", "%s("}, [394] = {"not implemented", "%s("},          \
  [395] = {"not implemented", "%s("}, [396] = {"not implemented", "%s("}, [397] = {"not implemented", "%s("},          \
  [398] = {"not implemented", "%s("}, [399] = {"not implemented", "%s("}, [400] = {"not implemented", "%s("},          \
  [401] = {"not implemented", "%s("}, [402] = {"not implemented", "%s("}, [403] = {"not implemented", "%s("},          \
  [404] = {"not implemented", "%s("}, [405] = {"not implemented", "%s("}, [406] = {"not implemented", "%s("},          \
  [407] = {"not implemented", "%s("}, [408] = {"not implemented", "%s("}, [409] = {"not implemented", "%s("},          \
  [410] = {"not implemented", "%s("}, [411] = {"not implemented", "%s("}, [412] = {"not implemented", "%s("},          \
  [413] = {"not implemented", "%s("}, [414] = {"not implemented", "%s("}, [415] = {"not implemented", "%s("},          \
  [416] = {"not implemented", "%s("}, [417] = {"not implemented", "%s("}, [418] = {"not implemented", "%s("},          \
  [419] = {"not implemented", "%s("}, [420] = {"not implemented", "%s("}, [421] = {"not implemented", "%s("},          \
  [422] = {"not implemented", "%s("}, [423] = {"not implemented", "%s("},                                              \
  [424] = {"pidfd_send_signal", "%s(%d, %d, %p, %d"}, [425] = {"io_uring_setup", "%s(%d, %p"},                         \
  [426] = {"io_uring_enter", "%s(%d, %d, %d, %d, %p"}, [427] = {"io_uring_register", "%s(%d, %d, %p, %d"},             \
  [428] = {"open_tree", "%s("}, [429] = {"move_mount", "%s("}, [430] = {"fsopen", "%s("}, [431] = {"fsconfig", "%s("}, \
  [432] = {"fsmount", "%s("}, [433] = {"fspick", "%s("}, [434] = {"pidfd_open", "%s("}, [435] = {"clone3", "%s("},     \
  [436] = {"close_range", "%s("}, [437] = {"openat2", "%s("}, [438] = {"pidfd_getfd", "%s("},                          \
  [439] = {"faccessat2", "%s("}, [440] = {"process_madvise", "%s("}
#endif // SYSCALLS_64_H
