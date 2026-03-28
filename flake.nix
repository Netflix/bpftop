{
  description = "bpftop - Dynamic real-time view of running eBPF programs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = fn:
        nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});
    in {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          # Nix's cc-wrapper injects hardening flags that are unsupported
          # by the BPF target (used by libbpf-cargo to compile .bpf.c files).
          # This is the same pattern used by systemd in nixpkgs.
          hardeningDisable = [ "zerocallusedregs" "shadowstack" "pacret" ];

          nativeBuildInputs = with pkgs; [
            # Rust
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer

            # Build tools
            pkg-config
            llvmPackages.clang
            gnumake

            # Libraries
            elfutils
            zlib
            libbpf
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      });
    };
}
