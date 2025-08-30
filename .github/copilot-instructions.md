# bpftop - Dynamic eBPF Program Monitor

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

bpftop is a dynamic real-time terminal UI view of running eBPF programs written in Rust. It displays runtime statistics, events per second, and CPU utilization for eBPF programs using ratatui for the terminal interface.

## Working Effectively

### Bootstrap and Build the Repository
Install required system dependencies first:
```bash
sudo apt-get update && sudo apt-get install -y zlib1g-dev libelf-dev clang libbpf-dev
```

Install the cross-compilation tool:
```bash
cargo install cross --git https://github.com/cross-rs/cross
```

### Build Commands
Use regular cargo for fast development builds:
```bash
# Build for development - takes ~30 seconds
cargo build

# Build release binary - takes ~45 seconds
cargo build --release
```

For cross-compilation (when needed):
```bash
# Build for x86_64 (may take 15+ minutes on first run due to Docker image building) 
# NEVER CANCEL: Set timeout to 120+ minutes for cross builds due to potential network issues
cross build --release --target x86_64-unknown-linux-gnu

# Build for ARM64 - takes 15+ minutes on first run
# NEVER CANCEL: Set timeout to 120+ minutes for cross builds due to potential network issues
cross build --release --target aarch64-unknown-linux-gnu

# Using make shortcut (calls cross build --release)
make build
```

### Testing
```bash
# Run all tests - takes ~30 seconds. NEVER CANCEL.
cargo test

# Run tests with cross-compilation
cross test --target x86_64-unknown-linux-gnu
```

### Code Quality
```bash
# Run clippy linter - takes ~15 seconds
cargo clippy --all --tests --all-features --no-deps

# Run clippy with cross-compilation
cross clippy --target x86_64-unknown-linux-gnu --all --tests --all-features --no-deps
```

## Running the Application

**CRITICAL**: bpftop requires sudo privileges to access BPF syscalls.

```bash
# Run the application (requires sudo)
sudo ./target/release/bpftop

# Run with custom refresh delay
sudo ./target/release/bpftop -d 2
```

The application displays:
- List of running eBPF programs with ID, type, and name
- Period and total average runtime for each program
- Events per second and estimated CPU utilization  
- Real-time graphical views (press Enter on a program)
- Updates every second

Controls: `q` to quit, `↑/↓` or `k/j` to navigate, `Enter` to show graphs, `f` to filter, `s` to sort.

## Validation

### Build Validation Steps
Always run these validation steps after making changes:
1. `cargo test` - ensures all unit tests pass (~30 seconds)
2. `cargo clippy --all --tests --all-features --no-deps` - ensures code quality (~15 seconds)  
3. `cargo build --release` - ensures release build works (~45 seconds)
4. `sudo timeout 5 ./target/release/bpftop` - ensures application starts and displays eBPF programs

### Manual Validation Scenarios
After making code changes, always test these scenarios:
1. **Basic functionality**: Run `sudo ./target/release/bpftop` and verify it displays a list of eBPF programs
2. **Navigation**: Use arrow keys or `j/k` to navigate through the program list
3. **Graph view**: Press Enter on a program to switch to graph view, then `q` to return to table view
4. **Program termination**: Press `q` to quit cleanly

### Cross-compilation Validation
If cross-compilation is needed:
```bash
# Test x86_64 build - NEVER CANCEL: may take 120+ minutes on first run due to Docker and network issues
cross build --target x86_64-unknown-linux-gnu --release

# Test ARM64 build - NEVER CANCEL: may take 120+ minutes on first run due to Docker and network issues
cross build --target aarch64-unknown-linux-gnu --release
```

**WARNING**: Cross-compilation builds Docker images which frequently fail with network connectivity issues to Ubuntu package repositories. If cross builds fail with "Temporary failure resolving" errors, this is a known issue. Use regular cargo builds for development and testing.

## Critical Build Information

### Timing Expectations
- **cargo test**: ~30 seconds - NEVER CANCEL, set timeout to 90+ seconds
- **cargo build**: ~30 seconds for debug, ~45 seconds for release - set timeout to 90+ seconds
- **cargo clippy**: ~15 seconds - set timeout to 60+ seconds
- **cross build**: 15-120+ minutes on first run (Docker image building with potential network issues) - NEVER CANCEL, set timeout to 150+ minutes
- **cross test**: 5-60+ minutes - NEVER CANCEL, set timeout to 90+ minutes

### Dependencies and Requirements
- **System packages**: zlib1g-dev, libelf-dev, clang, libbpf-dev
- **Rust toolchain**: Standard Rust installation with cargo
- **Cross-compilation**: cross tool (installs via cargo)
- **Runtime**: Linux with eBPF support, sudo privileges required

### Build Process Details
The project uses a custom build script (`build.rs`) that:
1. Compiles BPF C code (`src/bpf/pid_iter.bpf.c`) using libbpf-cargo
2. Generates Rust bindings (`pid_iter.skel.rs` in `$OUT_DIR`)
3. Uses SkeletonBuilder for BPF-to-Rust integration

This means changes to BPF C code require a full rebuild.

## Important Notes

- **Requires sudo**: The application MUST be run with sudo to access BPF syscalls
- **Platform support**: Primarily tested on Linux x86_64 and ARM64
- **BPF statistics**: Only enabled while the application is running to minimize system overhead
- **Real-time updates**: UI refreshes every second with new statistics
- **Cross-compilation issues**: Docker builds may fail due to Ubuntu package repository connectivity issues

## Common Issues

### Build Failures
- **Missing dependencies**: Install zlib1g-dev, libelf-dev, clang, libbpf-dev
- **Cross build Docker failures**: Use regular cargo builds if cross builds fail with network errors
- **Permission errors**: Ensure sudo access for running the application

### Runtime Issues  
- **"must be run as root"**: Use sudo to run the application
- **No eBPF programs shown**: Normal if no eBPF programs are currently loaded on the system
- **Terminal UI issues**: Ensure terminal supports ANSI colors and has sufficient size

## Repository Structure

Key files and directories:
- `src/main.rs`: Main entry point, terminal setup, BPF statistics collection
- `src/app.rs`: Application state management, UI modes, sorting/filtering
- `src/bpf_program.rs`: eBPF program data structures and statistics calculation
- `src/bpf/`: BPF C source code and header files
- `build.rs`: Build script for compiling BPF code and generating Rust bindings
- `Cross.toml`: Cross-compilation configuration
- `dockerfiles/`: Docker configurations for cross-compilation targets