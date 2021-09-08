{
  description = "Multipath tcp pcap analyzer tool";

  nixConfig = {
    substituters = [
      # https://iohk.cachix.org
      https://hydra.iohk.io
    ];
    trusted-public-keys = [
      hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ=
    ];
    # bash-prompt = "toto";
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/master";
    replica.url = "github:berewt/REPLica?rev=31ca9b01c61a0875137c8388fd50f9d70fdc5454";

    # temporary until this gets fixed upstream
    # poetry.url = "github:teto/poetry2nix/fix_tag";

    flake-utils.url = "github:numtide/flake-utils";

    hls.url = "github:haskell/haskell-language-server";
    # hls.url = "github:teto/haskell-language-server/flake-debug";

    # haskellNix.url = "github:input-output-hk/haskell.nix?ref=hkm/nixpkgs-unstable-update";
    haskellNix.url = "github:input-output-hk/haskell.nix";

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry, haskellNix, replica, ... }@inputs:
    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let

      compilerVersion = "8104";
      # compilerVersion = "901";

      ## haskell.nix trial
      overlays = [
        haskellNix.overlay
        (final: prev: {
          # This overlay adds our project to pkgs
          mptcpanalyzer =
            final.haskell-nix.project' {
              src = ./.;
              compiler-nix-name = "ghc${compilerVersion}";
            };
        })
      ];
      flake = pkgs.mptcpanalyzer.flake {};


      haskellOverlay = hnew: hold: with pkgs.haskell.lib; {

        # TODO override Frames
        ip = unmarkBroken (dontCheck hold.ip);
        bytebuild = unmarkBroken (dontCheck hold.bytebuild);

        # may not be needed anymore ?
        wide-word = unmarkBroken (dontCheck hold.wide-word);

        co-log-polysemy = doJailbreak (hold.co-log-polysemy);

        netlink = (overrideSrc hold.netlink {
          # src = builtins.fetchGit {
          #   # url = https://github.com/ongy/netlink-hs;
          #   url = https://github.com/teto/netlink-hs;
          # };
          version = "1.1.2.0";
          src = pkgs.fetchFromGitHub {
            owner = "teto";
            repo = "netlink-hs";
            rev = "090a48ebdbc35171529c7db1bd420d227c19b76d";
            sha256 = "sha256-qopa1ED4Bqk185b1AXZ32BG2s80SHDSkCODyoZfnft0=";
          };
        });

        mptcp-pm = overrideSrc hold.mptcp-pm {
          src = pkgs.fetchFromGitHub {
            owner = "teto";
            repo = "mptcp-pm";
            rev = "0cd4cad9bab5713ebbe529e194bddb08948825d7";
            sha256 = "sha256-7JhrMrv9ld12nx8LyfOuOPTBb7RyWIwSWNB9vWDe/g0=";
          };
        };
      };


      # pkgs = nixpkgs.legacyPackages."${system}";
      pkgs = import nixpkgs {
          inherit system overlays;
          # overlays = pkgs.lib.attrValues (self.overlays);
          config = { allowUnfree = true; allowBroken = true; };
        };

      myHaskellPackages = pkgs.haskell.packages."ghc${compilerVersion}";

      hsEnv = myHaskellPackages.ghcWithPackages(hs: [
        # hs.cairo
        # hs.diagrams
        # inputs.hls.packages."${system}"."haskell-language-server-${compilerVersion}"
        hs.cabal-install
        hs.stylish-haskell
        hs.hasktags
        # myHaskellPackages.hlint
        hs.stan
        pkgs.zlib
        hs.shelltestrunner
      ]);

    in rec {
      packages.mptcpanalyzer2 = flake.packages."mptcpanalyzer:exe:mptcpanalyzer";

      packages.mptcpanalyzer = pkgs.haskellPackages.developPackage {
        root = ./.;
        name = "mptcpanalyzer";
        returnShellEnv = false;
        withHoogle = true;
        overrides = haskellOverlay;
      };

      defaultPackage = packages.mptcpanalyzer;


      devShell = pkgs.mkShell {
        name = "dev-shell";
        buildInputs = with pkgs; [
          # defaultPackage.inputDerivation
          replica.packages."${system}".build
          inputs.hls.packages."${system}"."haskell-language-server-${compilerVersion}"
          haskellPackages.stan
          haskellPackages.threadscope
          cairo # for chart-cairo
          dhall-json  # for dhall-to-json
          glib
          hsEnv
          pkg-config
          zlib
          dhall-lsp-server
        ];

        shellHook = ''
          exe=$(cabal list-bin exe:mptcpanalyzer)
          PATH="$(dirname $exe):$PATH"
        '';
      };

    });
}
