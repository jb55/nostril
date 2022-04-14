{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [ secp256k1 openssl gdb ];
}
