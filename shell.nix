{ pkgs ? import <nixpkgs> {}}:

let
  llvm = pkgs.llvmPackages_21;
in
pkgs.mkShell {

    hardeningDisable = [ "stackprotector" "fortify" ];

    buildInputs = [
      pkgs.rustc
      pkgs.cargo
      pkgs.clippy
      pkgs.cmake
      pkgs.protobuf

      pkgs.rustfmt

      pkgs.bpftools

      # libbpf CO-RE pkgs
      #
      # use the unwrapped clang:
      # Since clang_15 this is needed to avoid running into:
      # cc-wrapper is currently not designed with multi-target compilers in mind. You may want to use an un-wrapped compiler instead.
      llvm.clang-unwrapped
      pkgs.elfutils
      pkgs.zlib
      pkgs.pkg-config
      pkgs.which
      pkgs.linuxHeaders

      # for code coverage:
      pkgs.cargo-tarpaulin

      # for integration tests
      pkgs.bitcoind
    ];

    shellHook = ''
      # during the integration tests, don't try to download a bitcoind binary
      # use the nix one instead
      export BITCOIND_SKIP_DOWNLOAD=1
      export BITCOIND_EXE=${pkgs.bitcoind}/bin/bitcoind

      # set the path of the Linux kernel headers. These are needed in
      # build.rs of the ebpf-extractor on Nix.
      export KERNEL_HEADERS=${pkgs.linuxHeaders}/include
    '';

    # Use for running integration tests
    NATS_SERVER_BINARY = "${pkgs.nats-server}/bin/nats-server";
}
