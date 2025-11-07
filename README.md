# bpftop

<img src="bpftop-logo.png" width="75" height="75">

`bpftop` provides a dynamic real-time view of running eBPF programs. It displays the average runtime, events per second, and estimated total CPU % for each program. It also provides graphical views of these statistics over time. This tool minimizes overhead by enabling performance statistics only while it is active.

![bpftop](bpftop.gif)

## Installation

To download the latest x86_64 release of `bpftop`, use the following command:

```bash
curl -fLJ https://github.com/Netflix/bpftop/releases/latest/download/bpftop-x86_64-unknown-linux-gnu -o bpftop && chmod +x bpftop
```

or install via your distribution's package manager:

[![Packaging status](https://repology.org/badge/vertical-allrepos/bpftop.svg)](https://repology.org/project/bpftop/versions)

### Fedora

You can install `bpftop` from the [official repositories](https://src.fedoraproject.org/rpms/bpftop) using [dnf](https://dnf.readthedocs.io/en/latest/):

```bash
sudo dnf install bpftop
```

### Arch Linux

You can install `bpftop` from the [official repositories](https://packages.fedoraproject.org/pkgs/bpftop/bpftop/) using [pacman](https://wiki.archlinux.org/title/pacman):

```bash
sudo pacman -S bpftop
```

### Nix
You can install bpftop from the NixOS 24.11 stable channel:

```
nix-channel --add https://nixos.org/channels/nixos-24.11 nixpkgs
nix-channel --update
nix-env -iA nixpkgs.bpftop
```

## Features

- **Real-time monitoring**: Displays a list of all running eBPF programs with ID, type, and name
- **Performance metrics**: Shows period and total average runtime, events per second, and estimated CPU utilization
- **Interactive navigation**: Navigate using arrow keys (↑/↓) or vim-style keys (j/k)
- **Time-series graphs**: Press Enter on a program to view graphical representations of performance metrics over time
- **Program filtering**: Press 'f' to filter programs by name or type
- **Column sorting**: Press 's' to sort by different columns (ascending/descending)
- **Process information**: Displays process names and PIDs that reference each eBPF program
- **Scrollbar navigation**: Automatically shows scrollbar when the program list exceeds terminal height
- **Customizable refresh rate**: Set update interval with `-d/--delay` option (1-3600 seconds)
- **Backward compatibility**: Supports Linux kernels from version 5.8+ (older kernels via procfs)
- **Minimal overhead**: Enables statistics gathering only while active, automatically disables on exit
- **Logging integration**: Logs to systemd journal when available

## Prerequisites

- `bpftop` requires `sudo` privileges to run.
- Linux kernel version 5.8 or later (older kernels supported via procfs fallback)
- The binary is dynamically linked to `libz` and `libelf`, so these libraries must be present on the systems where you intend to run `bpftop`.
- For logging functionality: systemd/journald (optional, will gracefully fallback if not available)

## Usage

Run the following command to start `bpftop` on your host:

```bash
sudo ./bpftop
```

### Command-line Options

- `-d, --delay <SECONDS>`: Set refresh interval (1-3600 seconds, default: 1)
- `-h, --help`: Show help information
- `-V, --version`: Show version information

Examples:
```bash
# Start with default 1-second refresh
sudo ./bpftop

# Update every 2 seconds
sudo ./bpftop -d 2

# Update every 5 seconds
sudo ./bpftop --delay 5
```

### Interactive Controls

Once running, use these keyboard shortcuts:

**Navigation:**
- `↑/↓` or `k/j`: Navigate up/down through the program list
- `Enter`: Switch to graphical view for the selected program
- `q`: Quit the application

**Features:**
- `f`: Filter programs by name or type
- `s`: Sort programs by different columns (use arrow keys to select column and direction)

**In graph view:**
- `Enter` or `q`: Return to the main program list

### Viewing Process Information

When you select a program, `bpftop` displays additional information including:
- Process names and PIDs that reference the selected eBPF program
- Detailed performance metrics and graphs

### Logging

`bpftop` logs operational information to the systemd journal when available. You can view these logs using:

```bash
journalctl _COMM=bpftop
```

Common log entries include:
- Application startup and shutdown
- Kernel version information
- BPF statistics enablement status
- Error conditions and debugging information

## Related links

* [Announcement blog post](https://netflixtechblog.com/announcing-bpftop-streamlining-ebpf-performance-optimization-6a727c1ae2e5)
* [LWN.net](https://lwn.net/Articles/963767/)
* [The New Stack](https://thenewstack.io/netflix-releases-bpftop-an-ebpf-based-application-monitor/)

## How it works

`bpftop` uses the [BPF_ENABLE_STATS](https://elixir.bootlin.com/linux/v6.6.16/source/include/uapi/linux/bpf.h#L792) BPF syscall command to enable global eBPF runtime statistics gathering, which is disabled by default to reduce performance overhead. It collects these statistics every second, calculating the average runtime, events per second, and estimated CPU utilization for each eBPF program within that sample period. This information is displayed in a top-like tabular format. Once `bpftop` terminates, it disables the statistics-gathering function by deleting the file descriptor returned by `BPF_ENABLE_STATS`.

## Building from source

### Prerequisites
Install required dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install -y zlib1g-dev libelf-dev clang libbpf-dev

# Fedora/RHEL
sudo dnf install -y zlib-devel elfutils-libelf-devel clang libbpf-devel
```

### Build Instructions

**For native builds:**
```bash
# Development build
cargo build

# Release build
cargo build --release
```

**For cross-compilation:**
1. Install and setup [cross](https://github.com/cross-rs/cross):
   ```bash
   cargo install cross --git https://github.com/cross-rs/cross
   ```

2. Build for target architectures:
   ```bash
   # x86_64
   cross build --release --target x86_64-unknown-linux-gnu
   
   # ARM64
   cross build --release --target aarch64-unknown-linux-gnu
   ```

Note: Cross-compilation builds may take 15+ minutes on first run due to Docker image building.

## Troubleshooting

### Common Issues

**"This program must be run as root"**
- Ensure you're running with `sudo` privileges. eBPF statistics collection requires root access.

**No programs displayed**
- This is normal if no eBPF programs are currently loaded on your system
- Try loading an eBPF program (e.g., using `bpftrace`, `bcc-tools`, or other eBPF utilities) to see them in bpftop

**Terminal display issues**
- Ensure your terminal supports ANSI colors and has sufficient size
- Minimum recommended terminal size: 80x24 characters

**Missing libraries error**
- Install the required system dependencies: `libz` and `libelf`
- On Ubuntu/Debian: `sudo apt-get install zlib1g-dev libelf-dev`

### Logging and Debugging

View application logs:
```bash
# View all bpftop logs
journalctl _COMM=bpftop

# Follow logs in real-time
journalctl _COMM=bpftop -f

# View logs from last boot
journalctl _COMM=bpftop -b
```

The logs include information about:
- Application startup and shutdown
- Kernel compatibility checks
- BPF statistics enablement method used
- Any errors or warnings encountered
