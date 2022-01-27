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
    nixpkgs.url = "github:nixos/nixpkgs/haskell-updates";
    replica.url = "github:ReplicaTest/REPLica";
    ihaskell.url = "github:gibiansky/IHaskell";

    flake-utils.url = "github:numtide/flake-utils";

    hls.url = "github:haskell/haskell-language-server/96ea854debd92f9a54e2270b9b9a080c0ce6f3d1";

    frames.url = "github:acowley/Frames";
    gtk2hs = {
      url = "github:teto/gtk2hs/ghc92";
      # pkgs.fetchzip {
      #   url = "https://github.com/teto/gtk2hs/archive/298e46920d850b450d10ceddd432fdcc106a7df4.tar.gz";
      #   sha256 = "sha256-bWnP7MpV10N/TqQVvS3cfRr7RG7pAR0FqPgerpwfzX4=";
      flake = false;
    };

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

  outputs = { self, all-cabal-hashes-unpacked, nixpkgs, flake-utils, poetry, replica, hls, frames, ... }:
    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let

      # compilerVersion = "8107";
      compilerVersion = "922";

      haskellOverlay = hnew: hold: with pkgs.haskell.lib;
        let
          gtk2hs-src = self.inputs.gtk2hs;
          # gtk2hs-src = pkgs.fetchzip {
          #     url = "https://github.com/teto/gtk2hs/archive/298e46920d850b450d10ceddd432fdcc106a7df4.tar.gz";
          #     sha256 = "sha256-bWnP7MpV10N/TqQVvS3cfRr7RG7pAR0FqPgerpwfzX4=";
          # };
          gtk2hs-buildtools = hnew.callCabal2nix "gtk2hs-buildtools" "${gtk2hs-src}/tools" {};

        in
        (pkgs.frameHaskellOverlay-921 hnew hold) //
        {

        # TODO override Frames
        ip = unmarkBroken (dontCheck hold.ip);
        bytebuild = unmarkBroken (dontCheck hold.bytebuild);
        size-based = overrideSrc (hold.size-based.overrideAttrs (oa: {
          patches = [];
        })) {
          src = pkgs.fetchFromGitHub {
            # owner = "byorgey";
            # rev = "fe6bf78a1b97ff7429630d0e8974c9bc40945dcf";
            owner = "teto";
            repo = "sized-functors";
            rev = "98f884032c1830f0b7046fac5e8e5e73ebf5facf";
            sha256 = "sha256-rQzO67AMP0Q95/aTKk76lalrV44RKqOs9g+W+Xd4W/M=";
          };
        };
          # https://github.com/byorgey/sized-functors.git

        relude = hold.relude_1_0_0_1;

        wide-word = hold.callCabal2nix "wide-word" (pkgs.fetchzip {
            url = "https://github.com/erikd/wide-word/archive/f2e17fc8fd6a9cea327ab0a72ca8b3c0367a2871.tar.gz";
            sha256 = "sha256-k91zTn1okIkvKQwOmZ+GFE3MfI6uSrPLPEhx0oDEONc=";
        }) {};

        polysemy = dontCheck hnew.polysemy_1_7_1_0;
        polysemy-plugin = hnew.polysemy-plugin_0_4_3_0;
        # polysemy-conc = hold.polysemy-conc_0_5_1_1;
        co-log-polysemy = doJailbreak (hold.co-log-polysemy);
        # co-log-core = doJailbreak hold.co-log-core_0_3_0_0;

        colourista = hold.callCabal2nix "colourista" (pkgs.fetchzip {
            url = "https://github.com/teto/colourista/archive/bf56469f7c2d9f226879831ed3a280f8f23be842.tar.gz";
            sha256 = "sha256-k91zTn1okIkvKQwOmZ+GFE0MfI6uSrPLPEhx0oDEONc=";
        }) {};

        inherit gtk2hs-buildtools ;

        # TODO see https://github.com/gtk2hs/gtk2hs/pull/310  and his fix at k0001/fix-cabal-3.6.0.0
        # use my fork instead
        # cairo = hnew.callCabal2nix "cairo" "${gtk2hs-src}/cairo"  {};
        cairo = hnew.callPackage ({ mkDerivation, array, base, bytestring, Cabal, cairo
        , gtk2hs-buildtools, lib, mtl, text, utf8-string
        }:
        mkDerivation {
          pname = "cairo";
          version = "0.13.8.2";
          src = /home/teto/mptcp/gtk2hs;
          postUnpack = "sourceRoot+=/cairo; echo source root reset to $sourceRoot";
          enableSeparateDataOutput = true;
          setupHaskellDepends = [ pkgs.gcc base Cabal gtk2hs-buildtools ];
          libraryHaskellDepends = [
            array base bytestring Cabal mtl text utf8-string
          ];
          libraryPkgconfigDepends = [ cairo ];
          homepage = "http://projects.haskell.org/gtk2hs/";
          description = "Binding to the Cairo library";
          license = lib.licenses.bsd3;
            }) {inherit (pkgs) cairo;};

        # polysemy-plugin = hnew.polysemy-plugin_0_4_3_0;
        # polysemy-conc = hold.polysemy-conc_0_5_1_1;
        # polysemy-test = hold.callCabal2nix "polysemy-test" (let src = pkgs.fetchzip {
        #     url = "https://github.com/tek/polysemy-test/archive/c83eb2a719e457e514d642a9d90651e69781c1d6.tar.gz";
        #     sha256 = "sha256-EB5r45FKOejQa9WMXYGePmayBCeRygE0mEGatCot3mM=";
        # }; in "${src}/packages/polysemy-test") {};

        type-errors = dontCheck hold.type-errors;
        # type-errors = hold.callCabal2nix "type-errors" (pkgs.fetchzip {
        #     url = "https://github.com/isovector/type-errors/archive/c73bd09eb7d1a7a6b5c61bd640c983496d0a9f8.tar.gz";
        #     sha256 = "sha256-Q5SxA+fazW/e60uPqJ3krBt2optFK37OoAxy00lEbw8=";
        # }) {};

        # chronos = hold.chronos_1_1_3;
        polysemy-test = hold.callHackage "polysemy-test" "0.5.0.0" {};

        netlink = overrideSrc hold.netlink {
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
        };
        haskell-src-meta = hold.haskell-src-meta.overrideAttrs (oa: {
          patches = [];
        });

        contiguous = hold.callCabal2nix "hashtables" (pkgs.fetchzip {
            url = "https://github.com/andrewthad/contiguous/archive/7771fc90e4a587b2c425b7c61a7a838c3b3d5fae.tar.gz";
            sha256 = "sha256-JahJAVxZM3xJUHTndl80mb4E8qMgqplMzSXCuYLKeOc=";
        }) {};
        hashtables = hold.callCabal2nix "hashtables" (pkgs.fetchzip {
            url = "https://github.com/gregorycollins/hashtables/archive/e07a3d73dee80b5c75d2e3bcc2023927b354ea7c.tar.gz";
            sha256 = "sha256-jjqm+o1viM28iWYf6ZuIu3fvQn/wcwwdbTWE6kP7QZE=";
        }) {};
        # we need >= 0.2.7.0
        byteslice = hold.callCabal2nix "byteslice" (pkgs.fetchzip {
            url = "https://github.com/byteverse/byteslice/archive/965e70d08c012b335104a6572ada68c6289482de.tar.gz";
            sha256 = "sha256-S3V0jSjXkAQxV0Zppgf6bkewf4mlQa5rkIWFbJ0eTBo=";
        }) {};

        mptcp = self.packages.${system}.mptcp;
      };

      pkgs = import nixpkgs {
          inherit system;
          overlays = [
            frames.overlay
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

      hsPkgs = pkgs.haskell.packages."ghc${compilerVersion}";

      # modifier used in haskellPackages.developPackage
      myModifier = drv:
        pkgs.haskell.lib.addBuildTools drv (with hsPkgs; [
          cabal-install
          replica.packages.${system}.build
          hls.packages.${system}."haskell-language-server-921"
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

    in {
      packages = {

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

      defaultPackage = self.packages.${system}.mptcpanalyzer;

      devShells = {
        mptcp = self.packages.${system}.mptcp.envFunc {};
        mptcp-pm = self.packages.${system}.mptcp-pm.envFunc {};

        mptcpanalyzer = let
          shell = self.packages.${system}.mptcpanalyzer.envFunc {};
        in shell.overrideAttrs(oa: {
          postShellHook = ''
              cd mptcpanalyzer
              set -x
              result=$(cabal list-bin exe:mptcpanalyzer)
              if [ $? -eq 0 ]; then
                export PATH="$(dirname $result):$PATH"
              fi
            '';
          });
      };
    });
}
