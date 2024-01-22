# Extended Security boX 

Improve the security of your system by restricting the systemcall.
 
## Requirements
`pkg-config gcc-multilib libclang-dev libelf-dev bpfcc-tools libbpf-dev linux-tools-common `
- Linux kernel version >= 5.10
Kernel should be compiled with at least the following build flags:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_TRACEPOINTS=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y

# (Note: This can also be set in kernel arguments via your bootloader, e.g. grub)
CONFIG_LSM="bpf"
```
## Start
`sudo cargo run daemon start`

## Audit mode
`sudo cargo run daemon --audit start  `
