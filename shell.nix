{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.go
  ];

  buildInputs = [
    pkgs.gnumake # optional; used by `make`
  ];
}
