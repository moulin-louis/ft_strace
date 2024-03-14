cmake_minimum_required(VERSION 3.22)
project(ft_strace C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-Wall -Werror -Wextra -g)
include_directories(./inc ./src/libft/inc)
add_subdirectory(./src/libft)

add_executable(ft_strace src/main.c
        inc/ft_strace.h)
target_link_libraries(ft_strace ft)