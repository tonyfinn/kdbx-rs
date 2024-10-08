{
  description = "Keepass Library for Rust";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        cargoToml = pkgs.lib.importTOML ./Cargo.toml;
        msrvToolchain = pkgs.rust-bin.stable.${cargoToml.package.rust-version}.default.override {
          extensions = ["rust-src"];
        };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "kdbx-rs";
          version = cargoToml.package.version;
          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo
            rustc
            clippy
            alejandra
          ];
          RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;
        };

        devShells.msrv = pkgs.mkShell {
          nativeBuildInputs = [
            msrvToolchain
          ];
        };
      }
    );
}
