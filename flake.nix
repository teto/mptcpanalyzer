{
  description = "Multipath tcp pcap analyzer tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    # temporary until this gets fixed upstream
    poetry.url = "github:teto/poetry2nix/fix_tag";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, poetry }: let
  in flake-utils.lib.eachDefaultSystem (system: let
    # myPoetry = poetry.legacyPackages.${system}.poetry2nix;
    myPoetry = poetry.packages."${system}".poetry2nix;
    in rec {

    packages.mptcpanalyzer = myPoetry.mkPoetryApplication {
      projectDir = ./.;
      preferWheels = false;
      overrides = myPoetry.overrides.withDefaults (self: super: {

        matplotlib = (super.matplotlib.override {enableGtk3=true;}).overrideAttrs(oa: {
          buildInputs = oa.buildInputs ++ [ nixpkgs.legacyPackages.${system}.pango ];
          strictDeps = false;
        });
      });
    };
    devShell = packages.mptcpanalyzer.overrideAttrs(oa: {
      postShellHook =  ''
        export PYTHONPATH=.:$PYTHONPATH
      '';
    });
    defaultPackage = packages.mptcpanalyzer;
  });
}
