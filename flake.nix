{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [(import rust-overlay)];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["rust-src" "rustfmt" "clippy" "rust-analyzer"];
        };

        workspaceToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

        hexyPkg = pkgs.rustPlatform.buildRustPackage {
          pname = "hexy";
          version = workspaceToml.workspace.package.version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = ["-p" "hexy-compat" "--bin" "hexy"];
          cargoTestFlags = ["-p" "hexy-core" "-p" "hexy-compat"];
          buildType = "release";
        };
      in {
        packages = {
          default = hexyPkg;
          hexy = hexyPkg;
          hexy-compat = hexyPkg;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            uv
          ];
        };
      }
    );
}
