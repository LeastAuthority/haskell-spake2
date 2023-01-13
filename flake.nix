{
  description = "spake2";

  inputs = {
    # Nix Inputs
    nixpkgs.url = github:nixos/nixpkgs/?ref=nixos-22.11;
    flake-utils.url = github:numtide/flake-utils;
    hs-flake-utils.url = "git+https://whetstone.private.storage/jcalderone/hs-flake-utils.git?ref=main";
    hs-flake-utils.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    hs-flake-utils,
  }: let
    ulib = flake-utils.lib;
  in
    ulib.eachSystem ["x86_64-linux"] (system: let
      hslib = hs-flake-utils.lib {
        pkgs = nixpkgs.legacyPackages.${system};
        src = ./.;
        compilerVersion = "ghc8107";
        packageName = "spake2";
      };
    in {
      checks = hslib.checks {};
      devShells = hslib.devShells {
        extraBuildInputs = pkgs: [
          (pkgs.python310.withPackages (ps: [ps.spake2 ps.attrs]))
        ];
      };
      packages = hslib.packages {};
    });
}
