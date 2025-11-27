{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [ scdoc ];
  nativeBuildInputs = [ autoreconfHook ];
}
