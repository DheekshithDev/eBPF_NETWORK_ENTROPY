cmake_minimum_required(VERSION 3.31)
project(Entropy_Project C)

set(CMAKE_C_STANDARD 11)

add_custom_command(
        OUTPUT entropy.bpf.o entropy.bpf.skel.h
        COMMAND clang -O2 -g -target bpf -c entropy.bpf.c -o entropy.bpf.o
        COMMAND bpftool gen skeleton entropy.bpf.o > entropy.bpf.skel.h
        DEPENDS entropy.bpf.c
)

add_custom_target(bpf_target ALL DEPENDS entropy.bpf.o entropy.bpf.skel.h)


add_executable(Entropy_Project main.c
#        entropy.bpf.c
#        entropy.bpf.h
        entropy.userspace.c
        entropy_uapi.h)

add_dependencies(Entropy_Project bpf_target)
include_directories(${CMAKE_SOURCE_DIR}/include)
target_include_directories(Entropy_Project PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(Entropy_Project bpf elf z)
set_target_properties(Entropy_Project PROPERTIES COMPILE_FLAGS "-g")
