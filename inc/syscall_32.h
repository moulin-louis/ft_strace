//
// Created by loumouli on 3/19/24.
//

//Copied from tsiguenz github

#ifndef SYSCALLS_32_H
#define SYSCALLS_32_H
// clang-format off
#define SYSCALLS_NBR_32 441
#define SYSCALLS_ENT_32                                                        \
[0] = { "restart_syscall", "%s(" },                                            \
[1] = { "exit", "%s(%d" },                                                     \
[2] = { "fork", "%s(" },                                                       \
[3] = { "read", "%s(%d, %p, %d" },                                              \
[4] = { "write", "%s(%d, \"%s\", %d" },                                        \
[5] = { "open", "%s(\"%s\", %d, %d" },                                         \
[6] = { "close", "%s(%d" },                                                    \
[7] = { "waitpid", "%s(%d, %p, %d" },                                          \
[8] = { "creat", "%s(\"%s\", %d" },                                            \
[9] = { "link", "%s(\"%s\", \"%s\"" },                                         \
[10] = { "unlink", "%s(\"%s\"" },                                              \
[11] = { "execve", "%s(\"%s\", %p, %p" },                                      \
[12] = { "chdir", "%s(\"%s\"" },                                               \
[13] = { "time", "%s(%p" },                                                    \
[14] = { "mknod", "%s(\"%s\", %d, 0x%lx" },                                    \
[15] = { "chmod", "%s(\"%s\", %d" },                                           \
[16] = { "lchown", "%s(\"%s\", %d, %d" },                                      \
[17] = { "break", "%s(?, ?, ?, ?, ?, ?" },                                     \
[18] = { "oldstat", "%s(?, ?, ?, ?, ?, ?" },                                   \
[19] = { "lseek", "%s(%d, %d, %d" },                                           \
[20] = { "getpid", "%s(" },                                                    \
[21] = { "mount", "%s(\"%s\", \"%s\", \"%s\", 0x%lx, %p" },                    \
[22] = { "umount", "%s(\"%s\", %d" },                                          \
[23] = { "setuid", "%s(%d" },                                                  \
[24] = { "getuid", "%s(" },                                                    \
[25] = { "stime", "%s(%p" },                                                   \
[26] = { "ptrace", "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx" },                          \
[27] = { "alarm", "%s(%d" },                                                   \
[28] = { "oldfstat", "%s(?, ?, ?, ?, ?, ?" },                                  \
[29] = { "pause", "%s(" },                                                     \
[30] = { "utime", "%s(\"%s\", %p" },                                           \
[31] = { "stty", "%s(?, ?, ?, ?, ?, ?" },                                      \
[32] = { "gtty", "%s(?, ?, ?, ?, ?, ?" },                                      \
[33] = { "access", "%s(\"%s\", %d" },                                          \
[34] = { "nice", "%s(%d" },                                                    \
[35] = { "ftime", "%s(?, ?, ?, ?, ?, ?" },                                     \
[36] = { "sync", "%s(" },                                                      \
[37] = { "kill", "%s(%d, %d" },                                                \
[38] = { "rename", "%s(\"%s\", \"%s\"" },                                      \
[39] = { "mkdir", "%s(\"%s\", %d" },                                           \
[40] = { "rmdir", "%s(\"%s\"" },                                               \
[41] = { "dup", "%s(%d" },                                                     \
[42] = { "pipe", "%s(%p" },                                                    \
[43] = { "times", "%s(%p" },                                                   \
[44] = { "prof", "%s(?, ?, ?, ?, ?, ?" },                                      \
[45] = { "brk", "%s(0x%lx" },                                                  \
[46] = { "setgid", "%s(%d" },                                                  \
[47] = { "getgid", "%s(" },                                                    \
[48] = { "signal", "%s(%d, 0x%lx" },                                           \
[49] = { "geteuid", "%s(" },                                                   \
[50] = { "getegid", "%s(" },                                                   \
[51] = { "acct", "%s(\"%s\"" },                                                \
[52] = { "umount2", "%s(?, ?, ?, ?, ?, ?" },                                   \
[53] = { "lock", "%s(?, ?, ?, ?, ?, ?" },                                      \
[54] = { "ioctl", "%s(%d, %d, 0x%lx" },                                        \
[55] = { "fcntl", "%s(%d, %d, 0x%lx" },                                        \
[56] = { "mpx", "%s(?, ?, ?, ?, ?, ?" },                                       \
[57] = { "setpgid", "%s(%d, %d" },                                             \
[58] = { "ulimit", "%s(?, ?, ?, ?, ?, ?" },                                    \
[59] = { "oldolduname", "%s(?, ?, ?, ?, ?, ?" },                               \
[60] = { "umask", "%s(%d" },                                                   \
[61] = { "chroot", "%s(\"%s\"" },                                              \
[62] = { "ustat", "%s(0x%lx, %p" },                                            \
[63] = { "dup2", "%s(%d, %d" },                                                \
[64] = { "getppid", "%s(" },                                                   \
[65] = { "getpgrp", "%s(" },                                                   \
[66] = { "setsid", "%s(" },                                                    \
[67] = { "sigaction", "%s(%d, %p, %p" },                                       \
[68] = { "sgetmask", "%s(" },                                                  \
[69] = { "ssetmask", "%s(%d" },                                                \
[70] = { "setreuid", "%s(%d, %d" },                                            \
[71] = { "setregid", "%s(%d, %d" },                                            \
[72] = { "sigsuspend", "%s(%d, %d, 0x%lx" },                                   \
[73] = { "sigpending", "%s(%p" },                                              \
[74] = { "sethostname", "%s(\"%s\", %d" },                                     \
[75] = { "setrlimit", "%s(%d, %p" },                                           \
[76] = { "getrlimit", "%s(%d, %p" },                                           \
[77] = { "getrusage", "%s(%d, %p" },                                           \
[78] = { "gettimeofday", "%s(%p, %p" },                                        \
[79] = { "settimeofday", "%s(%p, %p" },                                        \
[80] = { "getgroups", "%s(%d, %p" },                                           \
[81] = { "setgroups", "%s(%d, %p" },                                           \
[82] = { "select", "%s(%d, %p, %p, %p, %p" },                                  \
[83] = { "symlink", "%s(\"%s\", \"%s\"" },                                     \
[84] = { "oldlstat", "%s(?, ?, ?, ?, ?, ?" },                                  \
[85] = { "readlink", "%s(\"%s\", \"%s\", %d" },                                \
[86] = { "uselib", "%s(\"%s\"" },                                              \
[87] = { "swapon", "%s(\"%s\", %d" },                                          \
[88] = { "reboot", "%s(%d, %d, %d, %p" },                                      \
[89] = { "readdir", "%s(?, ?, ?, ?, ?, ?" },                                   \
[90] = { "mmap", "%s(%p, %lu, %d, %d, %d, %d" },                               \
[91] = { "munmap", "%s(0x%lx, %d" },                                           \
[92] = { "truncate", "%s(\"%s\", 0x%lx" },                                     \
[93] = { "ftruncate", "%s(%d, 0x%lx" },                                        \
[94] = { "fchmod", "%s(%d, %d" },                                              \
[95] = { "fchown", "%s(%d, %d, %d" },                                          \
[96] = { "getpriority", "%s(%d, %d" },                                         \
[97] = { "setpriority", "%s(%d, %d, %d" },                                     \
[98] = { "profil", "%s(?, ?, ?, ?, ?, ?" },                                    \
[99] = { "statfs", "%s(\"%s\", %p" },                                          \
[100] = { "fstatfs", "%s(%d, %p" },                                            \
[101] = { "ioperm", "%s(0x%lx, 0x%lx, %d" },                                   \
[102] = { "socketcall", "%s(%d, %p" },                                         \
[103] = { "syslog", "%s(%d, \"%s\", %d" },                                     \
[104] = { "setitimer", "%s(%d, %p, %p" },                                      \
[105] = { "getitimer", "%s(%d, %p" },                                          \
[106] = { "stat", "%s(\"%s\", %p" },                                           \
[107] = { "lstat", "%s(\"%s\", %p" },                                          \
[108] = { "fstat", "%s(%d, %p" },                                              \
[109] = { "olduname", "%s(%p" },                                               \
[110] = { "iopl", "%s(?, ?, ?, ?, ?, ?" },                                     \
[111] = { "vhangup", "%s(" },                                                  \
[112] = { "idle", "%s(" },                                                     \
[113] = { "vm86old", "%s(%p" },                                                \
[114] = { "wait4", "%s(%d, %p, %d, %p" },                                      \
[115] = { "swapoff", "%s(\"%s\"" },                                            \
[116] = { "sysinfo", "%s(%p" },                                                \
[117] = { "ipc", "%s(%d, %d, 0x%lx, 0x%lx, %p, 0x%lx" },                       \
[118] = { "fsync", "%s(%d" },                                                  \
[119] = { "sigreturn", "%s(" },                                                \
[120] = { "clone", "%s(0x%lx, 0x%lx, %p, %p, 0x%lx" },                         \
[121] = { "setdomainname", "%s(\"%s\", %d" },                                  \
[122] = { "uname", "%s(%p" },                                                  \
[123] = { "modify_ldt", "%s(?, ?, ?, ?, ?, ?" },                               \
[124] = { "adjtimex", "%s(%p" },                                               \
[125] = { "mprotect", "%s(0x%lx, %d, 0x%lx" },                                 \
[126] = { "sigprocmask", "%s(%d, %p, %p" },                                    \
[127] = { "create_module", "%s(?, ?, ?, ?, ?, ?" },                            \
[128] = { "init_module", "%s(%p, 0x%lx, \"%s\"" },                             \
[129] = { "delete_module", "%s(\"%s\", %d" },                                  \
[130] = { "get_kernel_syms", "%s(?, ?, ?, ?, ?, ?" },                          \
[131] = { "quotactl", "%s(%d, \"%s\", 0x%lx, %p" },                            \
[132] = { "getpgid", "%s(%d" },                                                \
[133] = { "fchdir", "%s(%d" },                                                 \
[134] = { "bdflush", "%s(%d, 0x%lx" },                                         \
[135] = { "sysfs", "%s(%d, 0x%lx, 0x%lx" },                                    \
[136] = { "personality", "%s(%d" },                                            \
[137] = { "afs_syscall", "%s(?, ?, ?, ?, ?, ?" },                              \
[138] = { "setfsuid", "%s(%d" },                                               \
[139] = { "setfsgid", "%s(%d" },                                               \
[140] = { "_llseek", "%s(?, ?, ?, ?, ?, ?" },                                  \
[141] = { "getdents", "%s(%d, %p, %d" },                                       \
[142] = { "_newselect", "%s(?, ?, ?, ?, ?, ?" },                               \
[143] = { "flock", "%s(%d, %d" },                                              \
[144] = { "msync", "%s(0x%lx, %d, %d" },                                       \
[145] = { "readv", "%s(0x%lx, %p, 0x%lx" },                                    \
[146] = { "writev", "%s(0x%lx, %p, 0x%lx" },                                   \
[147] = { "getsid", "%s(%d" },                                                 \
[148] = { "fdatasync", "%s(%d" },                                              \
[149] = { "_sysctl", "%s(?, ?, ?, ?, ?, ?" },                                  \
[150] = { "mlock", "%s(0x%lx, %d" },                                           \
[151] = { "munlock", "%s(0x%lx, %d" },                                         \
[152] = { "mlockall", "%s(%d" },                                               \
[153] = { "munlockall", "%s(" },                                               \
[154] = { "sched_setparam", "%s(%d, %p" },                                     \
[155] = { "sched_getparam", "%s(%d, %p" },                                     \
[156] = { "sched_setscheduler", "%s(%d, %d, %p" },                             \
[157] = { "sched_getscheduler", "%s(%d" },                                     \
[158] = { "sched_yield", "%s(" },                                              \
[159] = { "sched_get_priority_max", "%s(%d" },                                 \
[160] = { "sched_get_priority_min", "%s(%d" },                                 \
[161] = { "sched_rr_get_interval", "%s(%d, %p" },                              \
[162] = { "nanosleep", "%s(%p, %p" },                                          \
[163] = { "mremap", "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx" },                  \
[164] = { "setresuid", "%s(%d, %d, %d" },                                      \
[165] = { "getresuid", "%s(%p, %p, %p" },                                      \
[166] = { "vm86", "%s(?, ?, ?, ?, ?, ?" },                                     \
[167] = { "query_module", "%s(?, ?, ?, ?, ?, ?" },                             \
[168] = { "poll", "%s(%p, %d, %d" },                                           \
[169] = { "nfsservctl", "%s(?, ?, ?, ?, ?, ?" },                               \
[170] = { "setresgid", "%s(%d, %d, %d" },                                      \
[171] = { "getresgid", "%s(%p, %p, %p" },                                      \
[172] = { "prctl", "%s(%d, 0x%lx, 0x%lx, 0x%lx, 0x%lx" },                      \
[173] = { "rt_sigreturn", "%s(?, ?, ?, ?, ?, ?" },                             \
[174] = { "rt_sigaction", "%s(%d, %p, %p, %d" },                               \
[175] = { "rt_sigprocmask", "%s(%d, %p, %p, %d" },                             \
[176] = { "rt_sigpending", "%s(%p, %d" },                                      \
[177] = { "rt_sigtimedwait", "%s(%p, %p, %p, %d" },                            \
[178] = { "rt_sigqueueinfo", "%s(%d, %d, %p" },                                \
[179] = { "rt_sigsuspend", "%s(%p, %d" },                                      \
[180] = { "pread64", "%s(%d, \"%s\", %d, %d" },                                \
[181] = { "pwrite64", "%s(%d, \"%s\", %d, %d" },                               \
[182] = { "chown", "%s(\"%s\", %d, %d" },                                      \
[183] = { "getcwd", "%s(\"%s\", 0x%lx" },                                      \
[184] = { "capget", "%s(0x%lx, 0x%lx" },                                       \
[185] = { "capset", "%s(0x%lx, 0x%lx" },                                       \
[186] = { "sigaltstack", "%s(%p, %p" },                                        \
[187] = { "sendfile", "%s(%d, %d, %p, %d" },                                   \
[188] = { "getpmsg", "%s(?, ?, ?, ?, ?, ?" },                                  \
[189] = { "putpmsg", "%s(?, ?, ?, ?, ?, ?" },                                  \
[190] = { "vfork", "%s(" },                                                    \
[191] = { "ugetrlimit", "%s(?, ?, ?, ?, ?, ?" },                               \
[192] = { "mmap2", "%s(%p, %lu, %d, %d, %d, %d" },                             \
[193] = { "truncate64", "%s(\"%s\", %d" },                                     \
[194] = { "ftruncate64", "%s(%d, %d" },                                        \
[195] = { "stat64", "%s(\"%s\", %p" },                                         \
[196] = { "lstat64", "%s(\"%s\", %p" },                                        \
[197] = { "fstat64", "%s(0x%lx, %p" },                                         \
[198] = { "lchown32", "%s(?, ?, ?, ?, ?, ?" },                                 \
[199] = { "getuid32", "%s(?, ?, ?, ?, ?, ?" },                                 \
[200] = { "getgid32", "%s(?, ?, ?, ?, ?, ?" },                                 \
[201] = { "geteuid32", "%s(?, ?, ?, ?, ?, ?" },                                \
[202] = { "getegid32", "%s(?, ?, ?, ?, ?, ?" },                                \
[203] = { "setreuid32", "%s(?, ?, ?, ?, ?, ?" },                               \
[204] = { "setregid32", "%s(?, ?, ?, ?, ?, ?" },                               \
[205] = { "getgroups32", "%s(?, ?, ?, ?, ?, ?" },                              \
[206] = { "setgroups32", "%s(?, ?, ?, ?, ?, ?" },                              \
[207] = { "fchown32", "%s(?, ?, ?, ?, ?, ?" },                                 \
[208] = { "setresuid32", "%s(?, ?, ?, ?, ?, ?" },                              \
[209] = { "getresuid32", "%s(?, ?, ?, ?, ?, ?" },                              \
[210] = { "setresgid32", "%s(?, ?, ?, ?, ?, ?" },                              \
[211] = { "getresgid32", "%s(?, ?, ?, ?, ?, ?" },                              \
[212] = { "chown32", "%s(?, ?, ?, ?, ?, ?" },                                  \
[213] = { "setuid32", "%s(?, ?, ?, ?, ?, ?" },                                 \
[214] = { "setgid32", "%s(?, ?, ?, ?, ?, ?" },                                 \
[215] = { "setfsuid32", "%s(?, ?, ?, ?, ?, ?" },                               \
[216] = { "setfsgid32", "%s(?, ?, ?, ?, ?, ?" },                               \
[217] = { "pivot_root", "%s(\"%s\", \"%s\"" },                                 \
[218] = { "mincore", "%s(0x%lx, %d, \"%s\"" },                                 \
[219] = { "madvise", "%s(0x%lx, %d, %d" },                                     \
[220] = { "getdents64", "%s(%d, %p, %d" },                                     \
[221] = { "fcntl64", "%s(%d, %d, 0x%lx" },                                     \
[222] = { "not implemented", "%s(" },                                          \
[223] = { "not implemented", "%s(" },                                          \
[224] = { "gettid", "%s(" },                                                   \
[225] = { "readahead", "%s(%d, %d, %d" },                                      \
[226] = { "setxattr", "%s(\"%s\", \"%s\", %p, %d, %d" },                       \
[227] = { "lsetxattr", "%s(\"%s\", \"%s\", %p, %d, %d" },                      \
[228] = { "fsetxattr", "%s(%d, \"%s\", %p, %d, %d" },                          \
[229] = { "getxattr", "%s(\"%s\", \"%s\", %p, %d" },                           \
[230] = { "lgetxattr", "%s(\"%s\", \"%s\", %p, %d" },                          \
[231] = { "fgetxattr", "%s(%d, \"%s\", %p, %d" },                              \
[232] = { "listxattr", "%s(\"%s\", \"%s\", %d" },                              \
[233] = { "llistxattr", "%s(\"%s\", \"%s\", %d" },                             \
[234] = { "flistxattr", "%s(%d, \"%s\", %d" },                                 \
[235] = { "removexattr", "%s(\"%s\", \"%s\"" },                                \
[236] = { "lremovexattr", "%s(\"%s\", \"%s\"" },                               \
[237] = { "fremovexattr", "%s(%d, \"%s\"" },                                   \
[238] = { "tkill", "%s(%d, %d" },                                              \
[239] = { "sendfile64", "%s(%d, %d, %p, %d" },                                 \
[240] = { "futex", "%s(%p, %d, 0x%lx, %p, %p, 0x%lx" },                        \
[241] = { "sched_setaffinity", "%s(%d, %d, %p" },                              \
[242] = { "sched_getaffinity", "%s(%d, %d, %p" },                              \
[243] = { "set_thread_area", "%s(%p" },                                        \
[244] = { "get_thread_area", "%s(%p" },                                        \
[245] = { "io_setup", "%s(0x%lx, %p" },                                        \
[246] = { "io_destroy", "%s(0x%lx" },                                          \
[247] = { "io_getevents", "%s(0x%lx, 0x%lx, 0x%lx, %p, %p" },                  \
[248] = { "io_submit", "%s(0x%lx, 0x%lx, %p" },                                \
[249] = { "io_cancel", "%s(0x%lx, %p, %p" },                                   \
[250] = { "fadvise64", "%s(%d, %d, %d, %d" },                                  \
[251] = { "not implemented", "%s(" },                                          \
[252] = { "exit_group", "%s(%d" },                                             \
[253] = { "lookup_dcookie", "%s(0x%lx, \"%s\", %d" },                          \
[254] = { "epoll_create", "%s(%d" },                                           \
[255] = { "epoll_ctl", "%s(%d, %d, %d, %p" },                                  \
[256] = { "epoll_wait", "%s(%d, %p, %d, %d" },                                 \
[257] = { "remap_file_pages", "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx" },        \
[258] = { "set_tid_address", "%s(%p" },                                        \
[259] = { "timer_create", "%s(0x%lx, %p, %p" },                                \
[260] = { "timer_settime", "%s(0x%lx, %d, %p, %p" },                           \
[261] = { "timer_gettime", "%s(0x%lx, %p" },                                   \
[262] = { "timer_getoverrun", "%s(0x%lx" },                                    \
[263] = { "timer_delete", "%s(0x%lx" },                                        \
[264] = { "clock_settime", "%s(0x%lx, %p" },                                   \
[265] = { "clock_gettime", "%s(0x%lx, %p" },                                   \
[266] = { "clock_getres", "%s(0x%lx, %p" },                                    \
[267] = { "clock_nanosleep", "%s(0x%lx, %d, %p, %p" },                         \
[268] = { "statfs64", "%s(\"%s\", %d, %p" },                                   \
[269] = { "fstatfs64", "%s(%d, %d, %p" },                                      \
[270] = { "tgkill", "%s(%d, %d, %d" },                                         \
[271] = { "utimes", "%s(\"%s\", %p" },                                         \
[272] = { "fadvise64_64", "%s(%d, %d, %d, %d" },                               \
[273] = { "vserver", "%s(?, ?, ?, ?, ?, ?" },                                  \
[274] = { "mbind", "%s(0x%lx, 0x%lx, 0x%lx, %p, 0x%lx, 0x%lx" },               \
[275] = { "get_mempolicy", "%s(%p, %p, 0x%lx, 0x%lx, 0x%lx" },                 \
[276] = { "set_mempolicy", "%s(%d, %p, 0x%lx" },                               \
[277] = { "mq_open", "%s(\"%s\", %d, %d, %p" },                                \
[278] = { "mq_unlink", "%s(\"%s\"" },                                          \
[279] = { "mq_timedsend", "%s(0x%lx, \"%s\", %d, %d, %p" },                    \
[280] = { "mq_timedreceive", "%s(0x%lx, \"%s\", %d, %p, %p" },                 \
[281] = { "mq_notify", "%s(0x%lx, %p" },                                       \
[282] = { "mq_getsetattr", "%s(0x%lx, %p, %p" },                               \
[283] = { "kexec_load", "%s(0x%lx, 0x%lx, %p, 0x%lx" },                        \
[284] = { "waitid", "%s(%d, %d, %p, %d, %p" },                                 \
[285] = { "not implemented", "%s(" },                                          \
[286] = { "add_key", "%s(\"%s\", \"%s\", %p, %d, 0x%lx" },                     \
[287] = { "request_key", "%s(\"%s\", \"%s\", \"%s\", 0x%lx" },                 \
[288] = { "keyctl", "%s(%d, 0x%lx, 0x%lx, 0x%lx, 0x%lx" },                     \
[289] = { "ioprio_set", "%s(%d, %d, %d" },                                     \
[290] = { "ioprio_get", "%s(%d, %d" },                                         \
[291] = { "inotify_init", "%s(" },                                             \
[292] = { "inotify_add_watch", "%s(%d, \"%s\", 0x%lx" },                       \
[293] = { "inotify_rm_watch", "%s(%d, 0x%lx" },                                \
[294] = { "migrate_pages", "%s(%d, 0x%lx, %p, %p" },                           \
[295] = { "openat", "%s(%d, \"%s\", %d, %d" },                                 \
[296] = { "mkdirat", "%s(%d, \"%s\", %d" },                                    \
[297] = { "mknodat", "%s(%d, \"%s\", %d, 0x%lx" },                             \
[298] = { "fchownat", "%s(%d, \"%s\", %d, %d, %d" },                           \
[299] = { "futimesat", "%s(%d, \"%s\", %p" },                                  \
[300] = { "fstatat64", "%s(%d, \"%s\", %p, %d" },                              \
[301] = { "unlinkat", "%s(%d, \"%s\", %d" },                                   \
[302] = { "renameat", "%s(%d, \"%s\", %d, \"%s\"" },                           \
[303] = { "linkat", "%s(%d, \"%s\", %d, \"%s\", %d" },                         \
[304] = { "symlinkat", "%s(\"%s\", %d, \"%s\"" },                              \
[305] = { "readlinkat", "%s(%d, \"%s\", \"%s\", %d" },                         \
[306] = { "fchmodat", "%s(%d, \"%s\", %d" },                                   \
[307] = { "faccessat", "%s(%d, \"%s\", %d" },                                  \
[308] = { "pselect6", "%s(%d, %p, %p, %p, %p, %p" },                           \
[309] = { "ppoll", "%s(%p, %d, %p, %p, %d" },                                  \
[310] = { "unshare", "%s(0x%lx" },                                             \
[311] = { "set_robust_list", "%s(%p, %d" },                                    \
[312] = { "get_robust_list", "%s(%d, %p, %p" },                                \
[313] = { "splice", "%s(%d, %p, %d, %p, %d, %d" },                             \
[314] = { "sync_file_range", "%s(%d, %d, %d, %d" },                            \
[315] = { "tee", "%s(%d, %d, %d, %d" },                                        \
[316] = { "vmsplice", "%s(%d, %p, 0x%lx, %d" },                                \
[317] = { "move_pages", "%s(%d, 0x%lx, %p, %p, %p, %d" },                      \
[318] = { "getcpu", "%s(%p, %p, %p" },                                         \
[319] = { "epoll_pwait", "%s(%d, %p, %d, %d, %p, %d" },                        \
[320] = { "utimensat", "%s(%d, \"%s\", %p, %d" },                              \
[321] = { "signalfd", "%s(%d, %p, %d" },                                       \
[322] = { "timerfd_create", "%s(%d, %d" },                                     \
[323] = { "eventfd", "%s(%d" },                                                \
[324] = { "fallocate", "%s(%d, %d, %d, %d" },                                  \
[325] = { "timerfd_settime", "%s(%d, %d, %p, %p" },                            \
[326] = { "timerfd_gettime", "%s(%d, %p" },                                    \
[327] = { "signalfd4", "%s(%d, %p, %d, %d" },                                  \
[328] = { "eventfd2", "%s(%d, %d" },                                           \
[329] = { "epoll_create1", "%s(%d" },                                          \
[330] = { "dup3", "%s(%d, %d, %d" },                                           \
[331] = { "pipe2", "%s(%p, %d" },                                              \
[332] = { "inotify_init1", "%s(%d" },                                          \
[333] = { "preadv", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx" },                     \
[334] = { "pwritev", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx" },                    \
[335] = { "rt_tgsigqueueinfo", "%s(%d, %d, %d, %p" },                          \
[336] = { "perf_event_open", "%s(%p, %d, %d, %d, 0x%lx" },                     \
[337] = { "recvmmsg", "%s(%d, %p, %d, 0x%lx, %p" },                            \
[338] = { "fanotify_init", "%s(%d, %d" },                                      \
[339] = { "fanotify_mark", "%s(%d, %d, 0x%lx, %d, \"%s\"" },                   \
[340] = { "prlimit64", "%s(%d, %d, %p, %p" },                                  \
[341] = { "name_to_handle_at", "%s(%d, \"%s\", %p, %p, %d" },                  \
[342] = { "open_by_handle_at", "%s(%d, %p, %d" },                              \
[343] = { "clock_adjtime", "%s(0x%lx, %p" },                                   \
[344] = { "syncfs", "%s(%d" },                                                 \
[345] = { "sendmmsg", "%s(%d, %p, %d, 0x%lx" },                                \
[346] = { "setns", "%s(%d, %d" },                                              \
[347] = { "process_vm_readv", "%s(%d, %p, 0x%lx, %p, 0x%lx, 0x%lx" },          \
[348] = { "process_vm_writev", "%s(%d, %p, 0x%lx, %p, 0x%lx, 0x%lx" },         \
[349] = { "kcmp", "%s(%d, %d, %d, 0x%lx, 0x%lx" },                             \
[350] = { "finit_module", "%s(%d, \"%s\", %d" },                               \
[351] = { "sched_setattr", "%s(%d, %p, %d" },                                  \
[352] = { "sched_getattr", "%s(%d, %p, %d, %d" },                              \
[353] = { "renameat2", "%s(%d, \"%s\", %d, \"%s\", %d" },                      \
[354] = { "seccomp", "%s(%d, %d, %p" },                                        \
[355] = { "getrandom", "%s(\"%s\", %d, %d" },                                  \
[356] = { "memfd_create", "%s(\"%s\", %d" },                                   \
[357] = { "bpf", "%s(%d, %p, %d" },                                            \
[358] = { "execveat", "%s(%d, \"%s\", %p, %p, %d" },                           \
[359] = { "socket", "%s(%d, %d, %d" },                                         \
[360] = { "socketpair", "%s(%d, %d, %d, %p" },                                 \
[361] = { "bind", "%s(%d, %p, %d" },                                           \
[362] = { "connect", "%s(%d, %p, %d" },                                        \
[363] = { "listen", "%s(%d, %d" },                                             \
[364] = { "accept4", "%s(%d, %p, %p, %d" },                                    \
[365] = { "getsockopt", "%s(%d, %d, %d, \"%s\", %p" },                         \
[366] = { "setsockopt", "%s(%d, %d, %d, \"%s\", %d" },                         \
[367] = { "getsockname", "%s(%d, %p, %p" },                                    \
[368] = { "getpeername", "%s(%d, %p, %p" },                                    \
[369] = { "sendto", "%s(%d, %p, %d, 0x%lx, %p, %d" },                          \
[370] = { "sendmsg", "%s(%d, %p, 0x%lx" },                                     \
[371] = { "recvfrom", "%s(%d, %p, %d, 0x%lx, %p, %p" },                        \
[372] = { "recvmsg", "%s(%d, %p, 0x%lx" },                                     \
[373] = { "shutdown", "%s(%d, %d" },                                           \
[374] = { "userfaultfd", "%s(%d" },                                            \
[375] = { "membarrier", "%s(%d, %d" },                                         \
[376] = { "mlock2", "%s(0x%lx, %d, %d" },                                      \
[377] = { "copy_file_range", "%s(%d, %p, %d, %p, %d, %d" },                    \
[378] = { "preadv2", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx, %d" },                \
[379] = { "pwritev2", "%s(0x%lx, %p, 0x%lx, 0x%lx, 0x%lx, %d" },               \
[380] = { "pkey_mprotect", "%s(0x%lx, %d, 0x%lx, %d" },                        \
[381] = { "pkey_alloc", "%s(0x%lx, 0x%lx" },                                   \
[382] = { "pkey_free", "%s(%d" },                                              \
[383] = { "statx", "%s(%d, \"%s\", 0x%lx, 0x%lx, %p" },                        \
[384] = { "arch_prctl", "%s(%d, %p" },                                         \
[385] = { "io_pgetevents", "%s(" },                                            \
[386] = { "rseq", "%s(" },                                                     \
[387] = { "not_implemented", "%s(" },                                          \
[388] = { "not_implemented", "%s(" },                                          \
[389] = { "not_implemented", "%s(" },                                          \
[390] = { "not_implemented", "%s(" },                                          \
[391] = { "not_implemented", "%s(" },                                          \
[392] = { "not_implemented", "%s(" },                                          \
[393] = { "semget", "%s(" },                                                   \
[394] = { "semctl", "%s(" },                                                   \
[395] = { "shmget", "%s(" },                                                   \
[396] = { "shmctl", "%s(" },                                                   \
[397] = { "shmat", "%s(" },                                                    \
[398] = { "shmdt", "%s(" },                                                    \
[399] = { "msgget", "%s(" },                                                   \
[400] = { "msgsnd", "%s(" },                                                   \
[401] = { "msgrcv", "%s(" },                                                   \
[402] = { "msgctl", "%s(" },                                                   \
[403] = { "clock_gettime64", "%s(" },                                          \
[404] = { "clock_settime64", "%s(" },                                          \
[405] = { "clock_adjtime64", "%s(" },                                          \
[406] = { "clock_getres_time64", "%s(" },                                      \
[407] = { "clock_nanosleep_time64", "%s(" },                                   \
[408] = { "timer_gettime64", "%s(" },                                          \
[409] = { "timer_settime64", "%s(" },                                          \
[410] = { "timerfd_gettime64", "%s(" },                                        \
[411] = { "timerfd_settime64", "%s(" },                                        \
[412] = { "utimensat_time64", "%s(" },                                         \
[413] = { "pselect6_time64", "%s(" },                                          \
[414] = { "ppoll_time64", "%s(" },                                             \
[415] = { "not_implemented", "%s(" },                                          \
[416] = { "io_pgetevents_time64", "%s(" },                                     \
[417] = { "recvmmsg_time64", "%s(" },                                          \
[418] = { "mq_timedsend_time64", "%s(" },                                      \
[419] = { "mq_timedreceive_time64", "%s(" },                                   \
[420] = { "semtimedop_time64", "%s(" },                                        \
[421] = { "rt_sigtimedwait_time64", "%s(" },                                   \
[422] = { "futex_time64", "%s(" },                                             \
[423] = { "sched_rr_get_interval_time64", "%s(" },                             \
[424] = { "pidfd_send_signal", "%s(" },                                        \
[425] = { "io_uring_setup", "%s(" },                                           \
[426] = { "io_uring_enter", "%s(" },                                           \
[427] = { "io_uring_register", "%s(" },                                        \
[428] = { "open_tree", "%s(" },                                                \
[429] = { "move_mount", "%s(" },                                               \
[430] = { "fsopen", "%s(" },                                                   \
[431] = { "fsconfig", "%s(" },                                                 \
[432] = { "fsmount", "%s(" },                                                  \
[433] = { "fspick", "%s(" },                                                   \
[434] = { "pidfd_open", "%s(" },                                               \
[435] = { "clone3", "%s(" },                                                   \
[436] = { "close_range", "%s(" },                                              \
[437] = { "openat2", "%s(" },                                                  \
[438] = { "pidfd_getfd", "%s(" },                                              \
[439] = { "faccessat2", "%s(" },                                               \
[440] = { "process_madvise", "%s(" }
#endif  // SYSCALLS_32_H
