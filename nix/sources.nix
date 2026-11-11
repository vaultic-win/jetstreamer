# Pin both the native dependencies and the Rust toolchain metadata. Updating
# rust-toolchain.toml may also require a rust-overlay revision containing it.
{
  nixpkgs = builtins.fetchTarball {
    # nixos-26.05, checked 2026-11-11.
    url = "https://github.com/NixOS/nixpkgs/archive/ac588ef1c914865dad517b337ea0eb9694a4021c.tar.gz";
    sha256 = "1sxd2sqlpy1bx6b5xiwy1pbyygazl9d1a5yy0rvqfsihqpcibq2y";
  };
  rust-overlay = builtins.fetchTarball {
    url = "https://github.com/oxalica/rust-overlay/archive/0070500a3d72ade21323092e7bdd7125c5268482.tar.gz";
    sha256 = "0jqbqvl651g4hks9gq4p7cv885akssdxrr555d3fd6nd42929jxf";
  };
}
