let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs {
    overlays = [ (import sources.rust-overlay) ];
  };
  llvm = pkgs.llvmPackages;
  rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
in
(pkgs.mkShell.override { stdenv = pkgs.clangStdenv; }) {
  nativeBuildInputs = [
    rust
    llvm.clang
    pkgs.pkg-config
    pkgs.cmake
    pkgs.perl
    pkgs.protobuf
    pkgs.git
    pkgs.curl
  ];

  buildInputs = [
    llvm.libclang
    pkgs.openssl
    pkgs.zlib
  ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.systemd ];

  CC = "${llvm.clang}/bin/clang";
  CXX = "${llvm.clang}/bin/clang++";
  LIBCLANG_PATH = "${llvm.libclang.lib}/lib";
  OPENSSL_NO_VENDOR = "1";
}
