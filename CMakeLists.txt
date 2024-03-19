cmake_minimum_required(VERSION 3.22)
project(ft_strace C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-Wall -Werror -Wextra -g)
include_directories(./inc ./src/libft/inc)
add_subdirectory(./src/libft)

add_executable(ft_strace src/main.c
        inc/ft_strace.h
        inc/syscall_64.h
        src/signal_utils.c
        src/setup.c
        inc/syscall_32.h
        src/print.c
        src/string_manip.c
        src/path.c
        inc/errno.h)
target_link_libraries(ft_strace ft)