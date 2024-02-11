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
- The binary is dynamically linked to `libz` and `libelf`, so these libraries must be present on the systems where you intend to run `bpftop`.



