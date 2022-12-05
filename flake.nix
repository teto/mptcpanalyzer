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

    gtk2hs = { url = "github:teto/gtk2hs/ghc92"; flake = false; };

    ghc-typelits-natnormalise = { url = "github:clash-lang/ghc-typelits-natnormalise"; flake = false; };
    ghc-typelits-knownnat = { url = "github:clash-lang/ghc-typelits-knownnat"; flake = false; };
    double-conversion = { url = "github:haskell/double-conversion"; flake = false; };
    haskell-chart = { 
      url = "github:teto/haskell-chart/ghc92";
      # url = "github:timbod7/haskell-chart"; 
      flake = false;
    };

    bytebuild = { url = "github:parsonsmatt/bytebuild?ref=matt/support-ghc94"; 
    # url = "github:teto/bytebuild"; flake = false; 
    };
    bytesmith = { url = "github:parsonsmatt/bytesmith?ref=matt/support-ghc94"; flake = false; };
    haskell-ip = { url = "github:andrewthad/haskell-ip"; flake = false; };
    # bf20ee95b82414d96eb83863f50212e6c31b8930
    word-compat = { url = "github:fumieval/word-compat"; flake = false; };
    readable = { url = "github:istathar/readable/bump"; flake = false; };
    doctest = { url = "github:sol/doctest/ghc-9.4"; flake = false; };
    wide-word = { url = "github:parsonsmatt/wide-word?ref=matt/support-ghc94"; flake = false; };

    # cabal hashes contains all the version for different haskell packages, to update:
    # nix flake lock --update-input all-cabal-hashes-unpacked
    all-cabal-hashes-unpacked = {
      url = "github:commercialhaskell/all-cabal-hashes/current-hackage";
      flake = false;
    };

    polysemy = {
    # url = "github:polysemy-research/polysemy";
      url = "github:teto/polysemy/ghc94";
      flake = false;
    };

    polysemy-conc = { url = "github:tek/polysemy-conc"; flake = false; };
    polysemy-log = { url = "github:tek/polysemy-log"; flake = false; };

    flake-compat = { url = "github:edolstra/flake-compat"; flake = false; };

    typerep-map = { url = "github:parsonsmatt/typerep-map/?ref=matt/support-ghc-94"; flake = false; };
    
  };

  outputs = { self, haskell-chart, all-cabal-hashes-unpacked, nixpkgs, flake-utils, poetry, replica, hls, frames, ... }:
    let
      srcPackages = {
        # TODO use gitignore
        mptcp = ./mptcp;
        mptcp-pm = ./mptcp-pm;
        mptcpanalyzer = ./mptcpanalyzer;
      };
      compilerVersion = "943";
    in

    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let



      # extended = hpkgs:
        # (hpkgs.override (old: {
        #   overrides = lib.composeExtensions (old.overrides or (_: _: { }))
        #     haskellOverrides;
        # })).extend (hself: hsuper:
        #   # disable all checks for our packages
        #   builtins.mapAttrs (_: drv: haskell.lib.dontCheck drv)
        #   (lib.composeExtensions
        #     (haskell.lib.packageSourceOverrides hlsSources) tweaks hself
        #     hsuper));


      pkgs = import nixpkgs {
          inherit system;
          overlays = [
            # frames.overlay
            self.overlays.default
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

      hsPkgs = pkgs.haskell.packages."ghc${compilerVersion}".extend(pkgs.mptcpHaskellOverlay);

      # modifier used in haskellPackages.developPackage
      myModifier = drv:
        pkgs.haskell.lib.addBuildTools drv (with hsPkgs; [
          cabal-install
          replica.packages.${system}.build
          hls.packages.${system}."haskell-language-server-${compilerVersion}"
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
            # overrides = haskellOverlay;
            modifier = myModifier;
          };

      mkDevShell = name: self.packages.${system}.${name}.envFunc {};

      # provides a dev shell with libraries built by nix
      mkDevShellWithNix = name:
        # self.packages.${system}."${name}".envFunc {};
        # Returns a derivation whose environment contains a GHC with only
        hsPkgs.shellFor {
          inherit name;
          nativeBuildInputs = [
            hsPkgs.cabal-install
            hls.packages.${system}."haskell-language-server-${compilerVersion}"

          ];
          packages = p:
            [
              p.${name}
            ];
              # map (name: p.${name}) (attrNames
              # # Disable dependencies should not be part of the shell.
              # (removeAttrs hlsSources ));

            # src = null;
            doBenchmark = false;
            withHoogle = false;
          };

    in {
      packages = {

        inherit hsPkgs;

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
        default = mkDevShellWithNix "mptcp"; 
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

      overlays.default = final: prev: with final.haskell.lib;
        let

          # Change this to get debugging informations about Haskell packages.
          # thanks guibou
          debug = true;
          traceDebug = s: e: if debug then (builtins.trace s e) else e;
        in {
          haskellOverrides = hself: hsuper: {
            # we override mkDerivation here to apply the following
            # tweak to each haskell package:
            #   if the package is broken, then we disable its check and relax the cabal bounds;
            #   otherwise, we leave it unchanged.
            # hopefully, this could fix packages marked as broken by nix due to check failures
            # or the build failure because of tight cabal bounds
            mkDerivation = args:
              let
                broken = args.broken or false;
                check = args.doCheck or true;
                jailbreak = args.jailbreak or false;
              in hsuper.mkDerivation (args // {
                jailbreak = if broken then true else jailbreak;
                doCheck = if broken then false else check;
                # Library profiling is disabled as it causes long compilation time
                # on our CI jobs. Nix users are free tor revert this anytime.
                enableLibraryProfiling = false;
                doHaddock = false;
              });
            callHackage = pname: newVersion: args:
              let
                oldVersion = hprev.${pname}.version;
                pkg = hprev.callHackage pname newVersion args;
              in
              if builtins.compareVersions oldVersion newVersion == 1
              then traceDebug (pname + ": version " + newVersion + " is older than " + oldVersion) pkg
              else pkg;
        # (pkgs.frameHaskellOverlay-921 hfinal hprev) //
        # ((final.haskell.lib.packageSourceOverrides srcPackages) hfinal hprev) //

        # This version of callHackage compare the version we want to override
        # with the one available in nixpkgs and prints a debug (if debug is
        # enabled) if we force to an older version that what is inside nixpkgs.
        # Most of the time it means that we may use the nixpkgs version.


        # # # this repo software
        # # # mptcp = self.packages.${system}.mptcp;
        # # # mptcp-pm = self.packages.${system}.mptcp-pm;
        # # # mptcpanalyzer = self.packages.${system}.mptcpanalyzer;
        # })

         pcre = pcre.overrideAttrs(oa: {
           # /nix/store/fd8dhphf8lcb03yxiakkvbcsv5j8w9mw-pcre-8.45-dev/lib/pkgconfig/libpcre.pc
           preFixup = oa.preFixup + ''
             cp $out/lib/pkgconfig/libpcre.pc $out/lib/pkgconfig/libpcre2-8.pc
             '';
           });
  # postFixup = ''
  #   moveToOutput bin/pcre-config "$dev"
  # '' + optionalString (variant != null) ''
  #   ln -sf -t "$out/lib/" '${pcre.out}'/lib/libpcre{,posix}.{so.*.*.*,*dylib,*a}
  # '';


      };

      mptcpHaskellOverlay = 
          # TODO disable checks for ou packages
          (final.lib.composeManyExtensions [
            (final.haskell.lib.packageSourceOverrides srcPackages) 
            (import ./ghc94-overrides.nix { pkgs = final; inputs = self.inputs; })
          ]);
      };
    };
}
