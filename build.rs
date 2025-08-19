use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/pid_iter.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("pid_iter.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([OsStr::new("-I")])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
