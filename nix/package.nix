# The `auth` binary as a package. Single source of truth: used by the
# flake's packages output AND by the NixOS module's default package.
# The toolchain is the pinned nixpkgs rustc — reproducible through
# flake.lock, same as the dev toolchain is pinned through rust-overlay.
#
# The version must match Cargo.toml (pre-release; bumped by hand).
{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "dentrado-auth";
  version = "0.2.0";

  # The crate embeds the frontend at compile time (include_bytes! of
  # src/www/*), so the whole src/ tree is kept; tests/ feeds the
  # check phase (the integration suites are part of the release bar);
  # everything else in the repo is not part of the build.
  src = lib.cleanSourceWith {
    src = ./..;
    filter = path: type:
      let
        p = toString path;
        root = toString ./..;
      in
      p == root
      || p == root + "/Cargo.toml"
      || p == root + "/Cargo.lock"
      || lib.hasPrefix (root + "/src") p
      || lib.hasPrefix (root + "/tests") p;
  };

  cargoLock.lockFile = ../Cargo.lock;

  # The integration suite binds 127.0.0.1 sockets and writes redb
  # files under TMPDIR — fine inside the build sandbox.
  doCheck = true;

  meta = {
    description = "Dentrado identity service: WebAuthn login, session certs, enroll codes, attestations";
    license = lib.licenses.agpl3Only;
    mainProgram = "auth";
    platforms = lib.platforms.unix;
  };
}
