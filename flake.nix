{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      flake-parts,
      rust-overlay,
      crane,
      nixpkgs,
      git-hooks,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        git-hooks.flakeModule
      ];

      # The NixOS module can be imported standalone (it builds the
      # package from the same source via nix/package.nix), so no
      # overlay or self-reference is needed here.
      flake.nixosModules = {
        dentrado-auth = ./nix/module.nix;
        default = ./nix/module.nix;
      };

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { config, system, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
            targets = [ "wasm32-unknown-unknown" ];
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        in
        {
          pre-commit.settings.hooks = {
            rustfmt = {
              enable = true;
              package = rustToolchain;
            };
            clippy = {
              enable = true;
              package = rustToolchain;
            };
            cargo-deny = {
              enable = true;
              name = "Cargo deny check";
              entry = "${pkgs.cargo-deny}/bin/cargo-deny check";
              files = "(Cargo\\.(toml|lock)|deny\\.toml)$";
              pass_filenames = false;
            };
          };

          packages = rec {
            dentrado-auth = pkgs.callPackage ./nix/package.nix { };
            default = dentrado-auth;
          };

          devShells.default = pkgs.mkShell {
            name = "rust-nightly";

            shellHook = config.pre-commit.shellHook;

            packages = config.pre-commit.settings.enabledPackages ++ [
              rustToolchain
              pkgs.cargo-watch
              pkgs.cargo-deny
            ];
          };
        };
    };
}
