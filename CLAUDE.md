# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bpftop is a dynamic real-time view of running eBPF programs written in Rust. It displays runtime statistics, events per second, and CPU utilization for eBPF programs, using a TUI (Terminal User Interface) built with ratatui.

## Development Commands

### Building
```bash
# Build for x86_64 (default)
cross build --release

# Build for ARM64
cross build --target=aarch64-unknown-linux-gnu --release

# Using make
make build
```

### Testing
```bash
# Run tests for x86_64
cross test

# Run tests for specific target
cross test --target=aarch64-unknown-linux-gnu
```

### Code Quality
```bash
# Run clippy linter
cross clippy --all --tests --all-features --no-deps

# Run clippy for specific target
cross clippy --target=aarch64-unknown-linux-gnu --all --tests --all-features --no-deps
```

### Running
```bash
# Run the application (requires sudo privileges)
sudo ./target/release/bpftop
```

## Architecture

### Core Components

1. **Main Entry** (`src/main.rs`): Handles initialization, terminal setup, main event loop, and BPF statistics collection using `BPF_ENABLE_STATS` syscall.

2. **Application State** (`src/app.rs`): Manages UI state, sorting, filtering, and view modes (tabular vs graph views).

3. **BPF Program Data** (`src/bpf_program.rs`): Represents individual eBPF programs with their statistics and handles data collection/calculation.

4. **BPF Integration** (`src/bpf/`):
   - `pid_iter.bpf.c`: BPF C code for iterating over programs
   - `pid_iter.skel.rs`: Generated skeleton from BPF code (built via `build.rs`)
   - Helper headers for BPF development

### Key Dependencies

- **libbpf-rs**: Rust bindings for libbpf, used for BPF program interaction
- **ratatui**: Terminal UI framework for the interactive display
- **crossterm**: Terminal manipulation for cross-platform support
- **procfs**: Reading kernel version and system information

### Build Process

The project uses a build script (`build.rs`) that:
1. Compiles the BPF C code (`pid_iter.bpf.c`)
2. Generates Rust bindings (`pid_iter.skel.rs`)
3. Uses libbpf-cargo's SkeletonBuilder for BPF-to-Rust integration

### Important Notes

- Requires sudo privileges to run due to BPF syscall requirements
- Uses `cross` for cross-compilation to support multiple architectures
- BPF statistics are only collected while the application is running to minimize overhead
- The UI updates every second with new statistics