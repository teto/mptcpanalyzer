{ self, pkgs }:
hnew: hold: with pkgs.haskell.lib;
        let
          gtk2hs-src = self.inputs.gtk2hs;
          gtk2hs-buildtools = hnew.callCabal2nix "gtk2hs-buildtools" "${gtk2hs-src}/tools" {};
          chart-src = self.inputs.haskell-chart;

        in
        {
          # Frames = hold.callHackage "Frames" "0.1.4.0" {};
          Frames = hold.callCabal2nix "Frames" "${self.inputs.frames}" {};

        # readable = overrideSrc hold.readable {
        #   version = "matt-ghc923";
        #     src = self.inputs.readable;
        # } ;

        # TODO override Frames
        # ip = let
        #     newIp = (overrideSrc hold.ip { src = self.inputs.haskell-ip; });
        #   in doJailbreak (dontCheck (addBuildDepend newIp hnew.word-compat) );
        # circuithub:master
        # bytebuild = unmarkBroken (dontCheck hold.bytebuild);
        # bytebuild = overrideSrc hold.bytebuild { src = self.inputs.bytebuild; };
        # bytesmith = overrideSrc hold.bytesmith { src = self.inputs.bytesmith; };

        # vinyl  = hold.vinyl_0_14_3;
        #   active = doJailbreak hold.active;

        # chronos = overrideSrc hold.chronos {
        #   src = pkgs.fetchFromGitHub {
        #     # owner = "byorgey";
        #     # rev = "fe6bf78a1b97ff7429630d0e8974c9bc40945dcf";
        #     owner = "andrewthad";
        #     repo = "chronos";
        #     rev = "13b46574f2d811f27c693c78d92aed71c82f39d5";
        #     sha256 = "sha256-YZ4/5yfeUx+8jZp5nuEXjOkUvO4EWsvXrY+uX4e+VnI=";
        #   };
        # };

        # discussed at https://github.com/JonasDuregard/sized-functors/pull/10
        # 0.1.3.0 should be fine
        # size-based = hold.callHackage "size-based" "0.1.3.0" {};

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

        # relude = hold.relude_1_0_0_1;

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

        # htoml hasn't been updated since 2016 https://github.com/cies/htoml/pull/22
        # htoml = dontCheck (overrideSrc hold.htoml {
        #   # src = builtins.fetchGit {
        #   #   # url = https://github.com/ongy/netlink-hs;
        #   #   url = https://github.com/teto/netlink-hs;
        #   # };
        #   # version = "1.1.2.0";
        #   src = pkgs.fetchFromGitHub {
        #     owner = "mirokuratczyk";
        #     repo = "htoml";
        #     rev = "33971287445c5e2531d9605a287486dfc3cbe1da";
        #     sha256 = "sha256-BcHu+hzwSdf/11HEziCnNZ6lRrf5kEokfOU51XI9Rm0=";
        #   };
        # });

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

      }
