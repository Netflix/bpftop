# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bpftop is a dynamic real-time view of running eBPF programs written in Rust. It displays runtime statistics, events per second, and CPU utilization for eBPF programs, using a TUI (Terminal User Interface) built with ratatui.

## Development Commands

### Building
```bash
cargo build --release
```

### Testing
```bash
cargo test
```

### Code Quality
```bash
cargo clippy --all --tests --all-features --no-deps
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
- CI uses native GitHub ARM64 runners for aarch64 builds
- BPF statistics are only collected while the application is running to minimize overhead
- The UI updates every second with new statistics

## Conventions

### Rust Style
- Follow standard `rustfmt` formatting. Run `cargo fmt` before committing.
- All clippy warnings must pass: `cargo clippy --all --tests --all-features --no-deps`
- Prefer `anyhow::Result` for error propagation. Use `.context()` for meaningful error messages.
- Every `unsafe` block must have a `// SAFETY:` comment explaining why it is sound.
- Keep dependencies minimal. This is a single-binary tool — avoid pulling in large frameworks.

### BPF Code
- BPF C code lives in `src/bpf/`. Changes here require rebuilding via `build.rs`.
- BPF programs must pass the kernel verifier. Keep helpers simple and bounded.
- Do not modify `pid_iter.skel.rs` directly — it is generated.

### Commits
- Use conventional commit format: `type: lowercase description`
- Types: `feat`, `fix`, `chore`, `ci`, `docs`, `refactor`, `test`
- Write prose commit bodies explaining why, not what. No bullet lists.

### Pull Requests
- PRs must pass CI on both x86_64 and aarch64 before merging.
- Run `cargo clippy` and `cargo test` locally to catch issues early.
