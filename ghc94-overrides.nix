{ pkgs, inputs }:
hfinal: hprev:
with pkgs.haskell.lib;
{
        # TODO override Frames
        Frames = doJailbreak hprev.Frames;
        aeson = hfinal.callHackage "aeson" "2.1.1.0" {};
        ip = hfinal.callHackage "ip" "1.7.6" {};
         # 1.7.6
        # ip = let
         #    newIp = (overrideSrc hprev.ip { src = self.inputs.haskell-ip; });
        # in 
         #  # addBuildDepend newIp hfinal.word-compat
         #  doJailbreak (dontCheck (newIp) );
        # circuithub:master
        # bytebuild = unmarkBroken (dontCheck hprev.bytebuild);
        bytebuild = doJailbreak (overrideSrc hprev.bytebuild { src = self.inputs.bytebuild; });
        bytesmith = overrideSrc hprev.bytesmith { src = self.inputs.bytesmith; };
        #  doJailbreak hprev.base-compat; 
        tasty-hedgehog = doJailbreak (hfinal.callHackage "tasty-hedgehog" "1.3.1.0" {});
        # hedgehog 1.2
        hedgehog = dontHaddock (doJailbreak hprev.hedgehog); 
        base-compat = doJailbreak (hfinal.callHackage "base-compat" "0.12.2" {});
        base-compat-batteries = doJailbreak (hfinal.callHackage "base-compat-batteries" "0.12.2" {});

        # primitive = builtins.trace "toto" hprev.primitive_0_7_4_0;
        # primitive = builtins.trace "toto" (doJailbreak hprev.primitive);
        primitive = hfinal.callHackage "primitive" "0.7.4.0" {};

        zigzag = doJailbreak hprev.zigzag;
        doctest = dontCheck (overrideSrc hprev.doctest_0_20_0 { src = self.inputs.doctest; }); # doJailbreak hprev.doctest_0_20_0;
        ChasingBottoms = dontCheck (doJailbreak hprev.ChasingBottoms);
        singleton-bool =  doJailbreak hprev.singleton-bool;
        # tests create an infinite recursion with hspec -> primitive
        base-orphans = dontCheck hprev.base-orphans;
        discrimination = hfinal.callHackage "discrimination" "0.5" {};
        HTTP = doJailbreak hprev.HTTP;
        unordered-containers = doJailbreak hprev.unordered-containers;
        dec = doJailbreak hprev.dec;
        ed25519 = doJailbreak hprev.ed25519;
        boring = doJailbreak hprev.boring;
        hashable = hfinal.callHackage "hashable" "1.4.1.0" {};
        vector-binary-instances = doJailbreak hprev.vector-binary-instances;
        microlens-platform = doJailbreak hprev.microlens-platform;
        microlens  = doJailbreak hprev.microlens;
        lens = hfinal.callHackage "lens" "5.2" {};
        lens-aeson = doJailbreak hprev.lens-aeson;
        vector  = dontCheck hprev.vector;
        vinyl  = hprev.vinyl_0_14_3;
        active = doJailbreak hprev.active;
        some = doJailbreak hprev.some;
        incipit-base = doJailbreak hprev.incipit-base;
        #  hfinal.callHackage "typerep-map" "0.5.0.0" {}
        typerep-map = doJailbreak (overrideSrc hprev.typerep-map { src = self.inputs.typerep-map; });

        chronos = overrideSrc hprev.chronos {
          src = pkgs.fetchFromGitHub {
            # owner = "byorgey";
            # rev = "fe6bf78a1b97ff7429630d0e8974c9bc40945dcf";
            owner = "andrewthad";
            repo = "chronos";
            rev = "13b46574f2d811f27c693c78d92aed71c82f39d5";
            sha256 = "sha256-YZ4/5yfeUx+8jZp5nuEXjOkUvO4EWsvXrY+uX4e+VnI=";
          };
        };

        hspec-meta = hprev.callHackage "hspec-meta" "2.10.5" {};

        syb = dontCheck hprev.syb;

        cabal-install = doJailbreak hprev.cabal-install;
        cabal-install-solver = doJailbreak hprev.cabal-install-solver;
        double-conversion = overrideSrc hprev.double-conversion { src = self.inputs.double-conversion; };

        # discussed at https://github.com/JonasDuregard/sized-functors/pull/10
        # 0.1.3.0 should be fine
        size-based = hprev.callHackage "size-based" "0.1.3.1" {};
        ghc-tcplugins-extra = hprev.callHackage "ghc-tcplugins-extra" "0.4.3" {};
        # ghc-typelits-natnormalise = hprev.callHackage "ghc-typelits-natnormalise" "0.7.6" {};

        # see https://github.com/clash-lang/ghc-typelits-natnormalise/pull/64 for ghc 9.4
        ghc-typelits-natnormalise = doJailbreak (overrideSrc hprev.ghc-typelits-natnormalise { src = self.inputs.ghc-typelits-natnormalise; });
        ghc-typelits-knownnat = doJailbreak (overrideSrc hprev.ghc-typelits-knownnat { src = self.inputs.ghc-typelits-knownnat; });
          # doJailbreak (hprev.ghc-typelits-natnormalise.overrideAttrs(oa: {
        pipes-safe = doJailbreak hprev.pipes-safe;

        #
        primitive-unaligned = hprev.callHackage "primitive-unaligned" "0.1.1.2" {};
        hspec-discover = hprev.callHackage "hspec-discover" "2.10.6" {};
        hspec-core = hprev.callHackage "hspec-core" "2.10.6" {};
        hspec-contrib = dontCheck (hprev.callHackage "hspec-contrib" "0.5.1" {});
        hspec = hprev.callHackage "hspec" "2.10.6" {};
        incipit-core = doJailbreak hprev.incipit-core;

          # patches = [ ./toto.patch ];

        # }));

          # (addBuildDepend hprev.ghc-bignum hprev.ghc-typelits-natnormalise);
        # ghc-bignum = hfinal.ghc-bignum_1_3;

        # size-based = overrideSrc (hprev.size-based.overrideAttrs (oa: {
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
        # semirings = doJailbreak (hprev.semirings.overrideAttrs(oa: { propagatedBuildInputs = [ hfinal.base-compat-batteries ]; }));

        relude = hprev.relude_1_0_0_1;

        # TODO double check
        Chart = pkgs.lib.pipe hprev.Chart [ 
          (doJailbreak)
          (addBuildDepend hfinal.lens)
          # (overrideCabal (old: {
          #   libraryHaskellDepends = old.libraryHaskellDepends ++ [
          #     hfinal.lens
          #   ];
          # }))
        ];

        Chart-diagrams = doJailbreak hprev.Chart-diagrams;
        Chart-cairo = let 
          newCairo = hfinal.callCabal2nix "Chart-cairo" "${chart-src}/chart-cairo" {};
        in
          # newCairo;
          # doJailbreak (newCairo.overrideAttrs(oa: { propagatedBuildInputs = [ hfinal.Chart ]; }));
        # overrideCabal newCairo (old: { libraryHaskellDepends  = old.libraryHaskellDepends  ++ [ hfinal.Chart ]; }) ;
          # newCairo;
          pkgs.lib.pipe (newCairo) [ 
            # (addExtraLibrary hfinal.cairo )
            (addSetupDepend hfinal.cairo)
            ];

        # Chart-cairo = doJailbreak (hfinal.callCabal2nix "Chart-cairo" "${chart-src}/chart-cairo" {}) ;

        # overrideSrc hprev.wide-word { src = self.inputs.wide-word; }
        wide-word = doJailbreak (
          hprev.callCabal2nix "wide-word" ( self.inputs.wide-word) {}
          );

        # use flake
        htoml = dontCheck (overrideSrc hprev.htoml {
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

        readable = doJailbreak hprev.readable;
        # readable = throw "error";
        # readable = overrideSrc hprev.readable {
        #   version = "matt-ghc923";
        #     src = self.inputs.readable;
        # } ;

        # callCabal2nix
        invariant = doJailbreak  (hprev.invariant);
        polysemy-plugin = doJailbreak  (hfinal.callCabal2nix "polysemy-plugin" "${self.inputs.polysemy}/polysemy-plugin" {});
        polysemy = doJailbreak  (hfinal.callCabal2nix "polysemy-plugin" "${self.inputs.polysemy}" {});
        # polysemy-plugin = hfinal.polysemy-plugin_0_4_3_1;
        polysemy-conc = doJailbreak hprev.polysemy-conc; # hprev.polysemy-conc_0_5_1_1;
        # co-log-polysemy = doJailbreak (hprev.co-log-polysemy);
        co-log-polysemy = doJailbreak  (overrideSrc hprev.co-log-polysemy {
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
        co-log-core = doJailbreak hprev.co-log-core;

        # I think this can go away
        colourista = hprev.callCabal2nix "colourista" (pkgs.fetchzip {
            url = "https://github.com/teto/colourista/archive/bf56469f7c2d9f226879831ed3a280f8f23be842.tar.gz";
            sha256 = "sha256-k91zTn1okIkvKQwOmZ+GFE0MfI6uSrPLPEhx0oDEONc=";
        }) {};

        inherit gtk2hs-buildtools ;

        # TODO see https://github.com/gtk2hs/gtk2hs/pull/310  and his fix at k0001/fix-cabal-3.6.0.0
        # use my fork instead
        # cairo = hfinal.callCabal2nix "cairo" "${gtk2hs-src}/cairo"  {};
        # cairo = doJailbreak (hfinal.callPackage ({ mkDerivation, array, base, bytestring, Cabal, cairo
        # , gtk2hs-buildtools, lib, mtl, text, utf8-string
        # }:
        # mkDerivation {
        #   pname = "cairo";
        #   version = "0.13.8.2";
        #   src = "${gtk2hs-src}";
        #   postUnpack = "sourceRoot+=/cairo; echo source root reset to $sourceRoot";
        #   enableSeparateDataOutput = true;
        #   setupHaskellDepends = [ pkgs.gcc base Cabal gtk2hs-buildtools ];
        #   libraryHaskellDepends = [
        #     array base bytestring Cabal mtl text utf8-string
        #   ];
        #   libraryPkgconfigDepends = [ cairo ];
        #   homepage = "http://projects.haskell.org/gtk2hs/";
        #   description = "Binding to the Cairo library";
        #   license = lib.licenses.bsd3;
        #     }) {inherit (pkgs) cairo;});

        # polysemy-conc = hprev.polysemy-conc_0_5_1_1;
        # polysemy-test = hprev.callCabal2nix "polysemy-test" (let src = pkgs.fetchzip {
        #     url = "https://github.com/tek/polysemy-test/archive/c83eb2a719e457e514d642a9d90651e69781c1d6.tar.gz";
        #     sha256 = "sha256-EB5r45FKOejQa9WMXYGePmayBCeRygE0mEGatCot3mM=";
        # }; in "${src}/packages/polysemy-test") {};

        type-errors = dontCheck hprev.type-errors;
        # type-errors = hprev.callCabal2nix "type-errors" (pkgs.fetchzip {
        #     url = "https://github.com/isovector/type-errors/archive/c73bd09eb7d1a7a6b5c61bd640c983496d0a9f8.tar.gz";
        #     sha256 = "sha256-Q5SxA+fazW/e60uPqJ3krBt2optFK37OoAxy00lEbw8=";
        # }) {};

        # chronos = hprev.chronos_1_1_3;
        # polysemy-test = hprev.callHackage "polysemy-test" "0.5.0.0" {};

        netlink = overrideSrc hprev.netlink {
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
        haskell-src-meta = hprev.haskell-src-meta.overrideAttrs (oa: {
          patches = [];
        });

        contiguous = hprev.callCabal2nix "hashtables" (pkgs.fetchzip {
            url = "https://github.com/andrewthad/contiguous/archive/7771fc90e4a587b2c425b7c61a7a838c3b3d5fae.tar.gz";
            sha256 = "sha256-JahJAVxZM3xJUHTndl80mb4E8qMgqplMzSXCuYLKeOc=";
        }) {};
        hashtables = hprev.callCabal2nix "hashtables" (pkgs.fetchzip {
            url = "https://github.com/gregorycollins/hashtables/archive/e07a3d73dee80b5c75d2e3bcc2023927b354ea7c.tar.gz";
            sha256 = "sha256-jjqm+o1viM28iWYf6ZuIu3fvQn/wcwwdbTWE6kP7QZE=";
        }) {};
        # we need >= 0.2.7.0
        byteslice = hprev.callCabal2nix "byteslice" (pkgs.fetchzip {
            url = "https://github.com/byteverse/byteslice/archive/965e70d08c012b335104a6572ada68c6289482de.tar.gz";
            sha256 = "sha256-S3V0jSjXkAQxV0Zppgf6bkewf4mlQa5rkIWFbJ0eTBo=";
        }) {};

        # 
        word-compat = (doJailbreak (dontCheck (overrideSrc hprev.word-compat { src = self.inputs.word-compat; })));

}
