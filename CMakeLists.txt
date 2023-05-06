cmake_minimum_required(VERSION 3.23)
project(bpfesx C)

set(CMAKE_C_STANDARD 11)

include_directories(.)
include_directories(src/bpf/include)
include_directories(target)
include_directories(target/debug)
include_directories(target/debug/build)
include_directories(target/debug/build/libbpf-sys-b9986d0e850bd364)
include_directories(target/debug/build/libbpf-sys-b9986d0e850bd364/out)
include_directories(target/debug/build/libbpf-sys-b9986d0e850bd364/out/include)
include_directories(target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf)

add_executable(bpfesx
        src/bpf/include/audit.h
        src/bpf/include/const.h
        src/bpf/include/helpers.h
        src/bpf/include/kernel_defs.h
        src/bpf/include/policy.h
        src/bpf/include/structs.h
        src/bpf/include/user_types.h
        src/bpf/include/vmlinux_5.16.15.h
        src/bpf/bpfESX.bpf.c
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/bpf.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/bpf_core_read.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/bpf_endian.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/bpf_helper_defs.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/bpf_helpers.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/bpf_tracing.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/btf.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/libbpf.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/libbpf_common.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/libbpf_legacy.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/libbpf_version.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/skel_internal.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/usdt.bpf.h
        target/debug/build/libbpf-sys-b9986d0e850bd364/out/include/bpf/xsk.h
        bindings.h)
