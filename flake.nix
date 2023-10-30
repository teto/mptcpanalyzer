{
  description = "Multipath tcp pcap analyzer tool";

  nixConfig = {
    extra-substituters = [
      "https://haskell-language-server.cachix.org"
    ];
    extra-trusted-public-keys = [
      "haskell-language-server.cachix.org-1:juFfHrwkOxqIOZShtC4YC1uT1bBcq2RSvC7OMKx0Nz8="
    ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    replica.url = "github:ReplicaTest/REPLica";
    # ihaskell.url = "github:gibiansky/IHaskell";
    # ihaskell.url = "github:teto/IHaskell/ghc2-pr-nova";

    flake-utils.url = "github:numtide/flake-utils";

    hls.url = "github:haskell/haskell-language-server";

    frames.url = "github:acowley/Frames";

    gtk2hs = {
      url = "github:teto/gtk2hs/ghc92";
      flake = false;
    };

    haskell-chart = {
      url = "github:teto/haskell-chart/ghc92";
      # url = "github:timbod7/haskell-chart";
      flake = false;
    };

    # bytebuild = {
    #   url = "github:teto/bytebuild";
    #   flake = false;
    # };
    # bytesmith = {
    #   url = "github:teto/bytesmith/ghc92";
    #   flake = false;
    # };
    # haskell-ip = {
    #   url = "github:andrewthad/haskell-ip/ghc-9-2-3";
    #   flake = false;
    # };
    # word-compat = {
    #   # bf20ee95b82414d96eb83863f50212e6c31b8930
    #   url = "github:fumieval/word-compat/bf20ee95b82414d96eb83863f50212e6c31b8930";
    #   flake = false;
    # };

    # cabal hashes contains all the version for different haskell packages, to update:
    # nix flake lock --update-input all-cabal-hashes-unpacked
    all-cabal-hashes-unpacked = {
      url = "github:commercialhaskell/all-cabal-hashes/current-hackage";
      flake = false;
    };

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  # hls, 
  outputs = { self, all-cabal-hashes-unpacked, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system: let

      compilerVersion = "96";

      haskellOverlay = hnew: hold: with pkgs.haskell.lib;
        let
          gtk2hs-src = self.inputs.gtk2hs;
          gtk2hs-buildtools = hnew.callCabal2nix "gtk2hs-buildtools" "${gtk2hs-src}/tools" {};
          chart-src = self.inputs.haskell-chart;

        in
        # (pkgs.frameHaskellOverlay-921 hnew hold) 
        # //
        (pkgs.callPackage ./overlay-96.nix { inherit self; } hnew hold)
        // {

        # this repo software
        mptcp = self.packages.${system}.mptcp;
        mptcp-pm = self.packages.${system}.mptcp-pm;
        mptcpanalyzer = self.packages.${system}.mptcpanalyzer;
      };

      pkgs = import nixpkgs {
          inherit system;
          overlays = [
            # self.overlay
            (final: prev: {
              all-cabal-hashes = prev.runCommand "all-cabal-hashes.tar.gz"
                { }
                ''
                  cd ${all-cabal-hashes-unpacked}
                  cd ..
                  tar czf $out $(basename ${all-cabal-hashes-unpacked})
                '';
            })
          ];
          config = { allowUnfree = false; allowBroken = true;};
        };

      hsPkgs = pkgs.haskell.packages."ghc${compilerVersion}".extend( haskellOverlay );

      # modifier used in haskellPackages.developPackage
      myModifier = drv:
        pkgs.haskell.lib.addBuildTools drv (with hsPkgs; [
          cabal-install
          self.inputs.replica.packages.${system}.replica
          # hls.packages.${system}."haskell-language-server-${compilerVersion}"
          # ihaskell.packages.${system}."ihaskell-${compilerVersion}"
          # not available
          # hls.packages.${system}."hie-bios-${compilerVersion}"
          # cairo # for chart-cairo
          # dhall  # for the repl
          pkgs.dhall-json  # for dhall-to-json
          # glib
          hasktags
          # stan
          # pkg-config
          zlib
          # pkgs.dhall-lsp-server # broken
          # pkgs.stylish-haskell

          # we need the mptcp.h in mptcp-pm
          # pkgs.linuxHeaders
          # alternatively we could do makeLinuxHeaders pkgs.linux_latest.dev
          #   threadscope
        ]);

      mkPackage = name:
          hsPkgs.developPackage {
            root =  ./. + "/${name}";
            name = name;
            returnShellEnv = false;
            withHoogle = true;
            overrides = haskellOverlay;
            modifier = myModifier;
          };

      mkDevShell = name: self.packages.${system}."${name}".envFunc {};

      # provides a dev shell with libraries built by nix
      mkDevShellWithNix = name:
        # self.packages.${system}."${name}".envFunc {};
        # Returns a derivation whose environment contains a GHC with only
        hsPkgs.shellFor {
            packages = p:
              [p."${name}"];
              # map (name: p.${name}) (attrNames
              # # Disable dependencies should not be part of the shell.
              # (removeAttrs hlsSources ));

            # src = null;
          };

    in {

      legacyPackages.mptcpHaskellPkgs = hsPkgs;
      packages = {
        default = self.packages.${system}.mptcpanalyzer;

        # pkgs.haskell.lib.doJailbreak
        Chart-cairo = hsPkgs.Chart-cairo;
        # .overrideAttrs(oa: {
        #   # nativeBuildInputs = [ hsPkgs.Chart ];
        #   # propagatedBuildInputs = [ hsPkgs.Chart ];
        #   # buildInputs = [];
        #   # buildInputs = oa.buildInputs ++ [ hsPkgs.Chart ];

        # }));

        # basic library
        mptcp = mkPackage "mptcp";

        # path manager
        mptcp-pm = mkPackage "mptcp-pm";

        # pcap analysis
        mptcpanalyzer = let
          pkg = mkPackage "mptcpanalyzer";
        in
          pkg.overrideAttrs(oa: {
            nativeBuildInputs = (oa.nativeBuildInputs or []) ++ [ pkgs.installShellFiles ];
          });
      };

      # TODO add a shellFor (for all 3 packages)
      devShells = rec {

        default = mptcp;
        # cabal will provide the libraries
        # envFunc { withHoogle }
        mptcp = mkDevShell "mptcp";
        mptcp-pm = mkDevShell "mptcp-pm";

        # nix provides libraries in its environment
        mptcp-nix = mkDevShellWithNix "mptcp"; # self.packages.${system}.mptcp.envFunc {};
        mptcp-pm-nix = mkDevShellWithNix "mptcp-pm";

        mptcpanalyzer-nix = mkDevShellWithNix "mptcpanalyzer";
        # mptcpanalyzer = let
        #   shell = self.packages.${system}.mptcpanalyzer.envFunc {};
        # in shell.overrideAttrs(oa: {
        #   postShellHook = ''
        #       cd mptcpanalyzer
        #       set -x
        #       result=$(cabal list-bin exe:mptcpanalyzer)
        #       if [ $? -eq 0 ]; then
        #         export PATH="$(dirname $result):$PATH"
        #       fi
        #     '';
        #   });
      };
    }) // {

      overlay = final: prev: {
      };
    };
}
