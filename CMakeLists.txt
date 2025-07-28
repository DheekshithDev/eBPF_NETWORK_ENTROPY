cmake_minimum_required(VERSION 3.31)
project(Entropy_Project C)

set(CMAKE_C_STANDARD 11)

add_executable(Entropy_Project main.c
        entropy.bpf.c
        entropy.bpf.h
        entropy.userspace.c)

include_directories(${CMAKE_SOURCE_DIR}/include)
