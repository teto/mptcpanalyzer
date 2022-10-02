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
    ihaskell.url = "github:gibiansky/IHaskell";

    flake-utils.url = "github:numtide/flake-utils";

    hls.url = "github:haskell/haskell-language-server";

    frames.url = "github:acowley/Frames";

    gtk2hs = {
      url = "github:teto/gtk2hs/ghc92";
      flake = false;
    };

    ghc-typelits-natnormalise = {
      url = "github:clash-lang/ghc-typelits-natnormalise";
      flake = false;
    };

    ghc-typelits-knownnat = {
      url = "github:clash-lang/ghc-typelits-knownnat/941-support";
      flake = false;
    };

    double-conversion = {
      url = "github:haskell/double-conversion";
      flake = false;
    };

    haskell-chart = {
      url = "github:teto/haskell-chart/ghc92";
      # url = "github:timbod7/haskell-chart";
      flake = false;
    };

    bytebuild = {
      url = "github:teto/bytebuild";
      flake = false;
    };
    bytesmith = {
      url = "github:teto/bytesmith/ghc92";
      flake = false;
    };
    haskell-ip = {
      url = "github:andrewthad/haskell-ip/ghc-9-2-3";
      flake = false;
    };
    word-compat = {
      # bf20ee95b82414d96eb83863f50212e6c31b8930
      url = "github:fumieval/word-compat";
      flake = false;
    };
    readable = {
      url = "github:teto/readable/ghc921";
      flake = false;
    };
    doctest = {
      url = "github:sol/doctest/ghc-9.4";
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

  outputs = { self, haskell-chart, all-cabal-hashes-unpacked, nixpkgs, flake-utils, poetry, replica, hls, frames, ... }:
    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let

      compilerVersion = "942";

      haskellOverlay = hnew: hold: with pkgs.haskell.lib;
        let
          gtk2hs-src = self.inputs.gtk2hs;
          gtk2hs-buildtools = hnew.callCabal2nix "gtk2hs-buildtools" "${gtk2hs-src}/tools" {};
          chart-src = self.inputs.haskell-chart;

        in
        (pkgs.frameHaskellOverlay-921 hnew hold) //
        {

        # TODO override Frames
        ip = let
            newIp = (overrideSrc hold.ip { src = self.inputs.haskell-ip; });
          in doJailbreak (dontCheck (addBuildDepend newIp hnew.word-compat) );
        # circuithub:master
        # bytebuild = unmarkBroken (dontCheck hold.bytebuild);
        bytebuild = overrideSrc hold.bytebuild { src = self.inputs.bytebuild; };
        bytesmith = overrideSrc hold.bytesmith { src = self.inputs.bytesmith; };
        #  doJailbreak hold.base-compat; 
        base-compat = hold.callHackage "base-compat" "0.12.2" {};
        base-compat-batteries = hold.callHackage "base-compat-batteries" "0.12.2" {};
        primitive = hold.primitive_0_7_4_0;
        zigzag = doJailbreak hold.zigzag;
        doctest = doJailbreak hold.doctest_0_20_0;
        ChasingBottoms = dontCheck (doJailbreak hold.ChasingBottoms);
        singleton-bool =  doJailbreak hold.singleton-bool;
        # tests create an infinite recursion with hspec -> primitive
        base-orphans = dontCheck hold.base-orphans;
        unordered-containers = doJailbreak hold.unordered-containers;
        dec = doJailbreak hold.dec;
        ed25519 = doJailbreak hold.ed25519;
        boring = doJailbreak hold.boring;
        hashable = hold.callHackage "hashable" "1.4.1.0" {};

        vinyl  = hold.vinyl_0_14_3;
        active = doJailbreak hold.active;
        some = doJailbreak hold.some;
        incipit-base = doJailbreak hold.incipit-base;

        chronos = overrideSrc hold.chronos {
          src = pkgs.fetchFromGitHub {
            # owner = "byorgey";
            # rev = "fe6bf78a1b97ff7429630d0e8974c9bc40945dcf";
            owner = "andrewthad";
            repo = "chronos";
            rev = "13b46574f2d811f27c693c78d92aed71c82f39d5";
            sha256 = "sha256-YZ4/5yfeUx+8jZp5nuEXjOkUvO4EWsvXrY+uX4e+VnI=";
          };
        };

        hspec-meta = hold.callHackage "hspec-meta" "2.10.5" {};

        syb = dontCheck hold.syb;

        cabal-install-solver = doJailbreak hold.cabal-install-solver;
        double-conversion = overrideSrc hold.double-conversion { src = self.inputs.double-conversion; };

        # discussed at https://github.com/JonasDuregard/sized-functors/pull/10
        # 0.1.3.0 should be fine
        size-based = hold.callHackage "size-based" "0.1.3.1" {};
        ghc-tcplugins-extra = hold.callHackage "ghc-tcplugins-extra" "0.4.3" {};
        # ghc-typelits-natnormalise = hold.callHackage "ghc-typelits-natnormalise" "0.7.6" {};

        # see https://github.com/clash-lang/ghc-typelits-natnormalise/pull/64 for ghc 9.4
        ghc-typelits-natnormalise = doJailbreak (overrideSrc hold.ghc-typelits-natnormalise { src = self.inputs.ghc-typelits-natnormalise; });
        ghc-typelits-knownnat = doJailbreak (overrideSrc hold.ghc-typelits-knownnat { src = self.inputs.ghc-typelits-knownnat; });
          # doJailbreak (hold.ghc-typelits-natnormalise.overrideAttrs(oa: {
        pipes-safe = doJailbreak hold.pipes-safe;

        #
        primitive-unaligned = hold.callHackage "primitive-unaligned" "0.1.1.2" {};
        hspec-discover = hold.callHackage "hspec-discover" "2.10.6" {};
        hspec-core = hold.callHackage "hspec-core" "2.10.6" {};
        hspec-contrib = dontCheck (hold.callHackage "hspec-contrib" "0.5.1" {});
        hspec = hold.callHackage "hspec" "2.10.6" {};
        incipit-core = doJailbreak hold.incipit-core;

          # patches = [ ./toto.patch ];

        # }));

          # (addBuildDepend hold.ghc-bignum hold.ghc-typelits-natnormalise);
        # ghc-bignum = hnew.ghc-bignum_1_3;

        # size-based = overrideSrc (hold.size-based.overrideAttrs (oa: {
        #   patches = [];
        # # })) {
        #   src = pkgs.fetchFromGitHub {
        #     # owner = "byorgey";
        #     # rev = "fe6bf78a1b97ff7429630d0e8974c9bc40945dcf";
        #     owner = "teto";
        #     repo = "sized-functors";
        #     rev = "98f884032c1830f0b7046fac5e8e5e73ebf5facf";
        #     sha256 = "sha256-rQzO67AMP0Q95/aTKk76lalrV44RKqOs9g+W+Xd4W/M=";
        #   };
        # };
          # https://github.com/byorgey/sized-functors.git
        semirings = doJailbreak (hold.semirings.overrideAttrs(oa: { propagatedBuildInputs = [ hnew.base-compat-batteries ]; }));

        relude = hold.relude_1_0_0_1;

        # TODO double check
        Chart = pkgs.lib.pipe hold.Chart [ 
          (doJailbreak)
          (addBuildDepend hnew.lens)
          # (overrideCabal (old: {
          #   libraryHaskellDepends = old.libraryHaskellDepends ++ [
          #     hnew.lens
          #   ];
          # }))
        ];

        Chart-diagrams = doJailbreak hold.Chart-diagrams;
        Chart-cairo = let 
          newCairo = hnew.callCabal2nix "Chart-cairo" "${chart-src}/chart-cairo" {};
        in
          # newCairo;
          # doJailbreak (newCairo.overrideAttrs(oa: { propagatedBuildInputs = [ hnew.Chart ]; }));
        # overrideCabal newCairo (old: { libraryHaskellDepends  = old.libraryHaskellDepends  ++ [ hnew.Chart ]; }) ;
          # newCairo;
          pkgs.lib.pipe (newCairo) [ 
            # (addExtraLibrary hnew.cairo )
            (addSetupDepend hnew.cairo)
            ];

        # Chart-cairo = doJailbreak (hnew.callCabal2nix "Chart-cairo" "${chart-src}/chart-cairo" {}) ;

        wide-word = hold.callCabal2nix "wide-word" (pkgs.fetchzip {
            url = "https://github.com/erikd/wide-word/archive/f2e17fc8fd6a9cea327ab0a72ca8b3c0367a2871.tar.gz";
            sha256 = "sha256-k91zTn1okIkvKQwOmZ+GFE3MfI6uSrPLPEhx0oDEONc=";
        }) {};

        htoml = dontCheck (overrideSrc hold.htoml {
          # src = builtins.fetchGit {
          #   # url = https://github.com/ongy/netlink-hs;
          #   url = https://github.com/teto/netlink-hs;
          # };
          # version = "1.1.2.0";
          src = pkgs.fetchFromGitHub {
            owner = "mirokuratczyk";
            repo = "htoml";
            rev = "33971287445c5e2531d9605a287486dfc3cbe1da";
            sha256 = "sha256-BcHu+hzwSdf/11HEziCnNZ6lRrf5kEokfOU51XI9Rm0=";
          };
        });

        readable = doJailbreak hold.readable;
        # readable = throw "error";
        # readable = overrideSrc hold.readable {
        #   version = "matt-ghc923";
        #     src = self.inputs.readable;
        # } ;

        polysemy = dontCheck hnew.polysemy_1_7_1_0;
        polysemy-plugin = hnew.polysemy-plugin_0_4_3_1;
        # polysemy-conc = hold.polysemy-conc_0_5_1_1;
        # co-log-polysemy = doJailbreak (hold.co-log-polysemy);
        co-log-polysemy = doJailbreak  (overrideSrc hold.co-log-polysemy {
          # src = builtins.fetchGit {
          #   # url = https://github.com/ongy/netlink-hs;
          #   url = https://github.com/teto/netlink-hs;
          # };
          # version = "1.1.2.0";
          src = pkgs.fetchFromGitHub {
            # //tree/ghc-9.2
            owner = "alaendle";
            repo = "co-log-polysemy";
            rev = "b4f96240179b486047ff4d80c978e8efcac8ac7e";
            sha256 = "sha256-QFjNzRSr/pb1nw4UBsg8uWBOkO+7ffpuYrUfLUuashM=";
          };
        });
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
          src = "${gtk2hs-src}";
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
        # polysemy-test = hold.callHackage "polysemy-test" "0.5.0.0" {};

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

        # 
        word-compat = (doJailbreak (dontCheck (overrideSrc hold.word-compat { src = self.inputs.word-compat; })));

        # this repo software
        mptcp = self.packages.${system}.mptcp;
        mptcp-pm = self.packages.${system}.mptcp-pm;
        mptcpanalyzer = self.packages.${system}.mptcpanalyzer;
      };

      pkgs = import nixpkgs {
          inherit system;
          overlays = [
            frames.overlay
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
          replica.packages.${system}.build
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
      packages = {

        # pkgs.haskell.lib.doJailbreak
        # Chart-cairo = hsPkgs.Chart-cairo;
        # ghc-type = hsPkgs.Chart-cairo;
        inherit hsPkgs;
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

      defaultPackage = self.packages.${system}.mptcpanalyzer;

      # TODO add a shellFor (for all 3 packages)
      devShells = {
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
