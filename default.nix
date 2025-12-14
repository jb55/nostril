{ pkgs ? import <nixpkgs> {} }:

with pkgs;
stdenv.mkDerivation {
  pname = "nostril";
  version = "0.1";

  src = ./.;

  makeFlags = [ "PREFIX=$(out)" ];

  nativeBuildInputs = [ autoconf automake gettext libtool getopt ];
}
