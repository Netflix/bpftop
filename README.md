# bpftop

`bpftop` is a performance profiling command-line tool for eBPF programs. It provides a real-time view of all active eBPF programs, along with their average runtime per invocation. The tool is designed to minimize overhead by enabling performance statistics only while it is active.

![bpftop](https://github.com/Netflix/bpftop/blob/main/bpftop.png?raw=true)

## Features

- Display a list of all running eBPF programs on the host
- Show the average runtime for each eBPF program
- Dynamically update the list every second
- Low overhead by enabling performance profiling only during program execution

## Prerequisites

- `bpftop` requires `sudo` privileges to run.
- The Linux kernel version must be 5.8 or later.
- The binary is dynamically linked to `libz` and `libelf`, so these libraries must be present on the systems where you intend to run `bpftop`.

## How it works

`bpftop` uses the [BPF_ENABLE_STATS](https://elixir.bootlin.com/linux/v6.6.16/source/include/uapi/linux/bpf.h#L792) BPF syscall command to enable global eBPF runtime statistics gathering, which is disabled by default to reduce performance overhead. It collects these statistics every second, calculating the average runtime, events per second, and estimated CPU utilization for each eBPF program within that sample period. This information is displayed in a top-like tabular format. Once `bpftop` terminates, it disables the statistics-gathering function by deleting the file descriptor returned by `BPF_ENABLE_STATS`.