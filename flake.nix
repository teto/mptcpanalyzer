{
  description = "Multipath tcp pcap analyzer tool";

  nixConfig = {
    substituters = [
      "https://haskell-language-server.cachix.org"
    ];
    trusted-public-keys = [
      "haskell-language-server.cachix.org-1:juFfHrwkOxqIOZShtC4YC1uT1bBcq2RSvC7OMKx0Nz8="
    ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    replica.url = "github:ReplicaTest/REPLica";

    flake-utils.url = "github:numtide/flake-utils";

    hls.url = "github:haskell/haskell-language-server";

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry, replica, hls, ... }:
    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let

      compilerVersion = "8107";
      # compilerVersion = "901";

      haskellOverlay = hnew: hold: with pkgs.haskell.lib; {

        # TODO override Frames
        ip = unmarkBroken (dontCheck hold.ip);
        bytebuild = unmarkBroken (dontCheck hold.bytebuild);

        relude = hold.relude_1_0_0_1;

        # may not be needed anymore ?
        wide-word = unmarkBroken (dontCheck hold.wide-word);
        polysemy = hnew.polysemy_1_7_1_0;
        co-log-polysemy = doJailbreak (hold.co-log-polysemy);
        polysemy-plugin = hnew.polysemy-plugin_0_4_3_0;

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

      };

      pkgs = import nixpkgs {
          inherit system;
          # overlays = pkgs.lib.attrValues (self.overlays);
          config = { allowUnfree = false; allowBroken = true;};
        };

      hsPkgs = pkgs.haskell.packages."ghc${compilerVersion}";

      # modifier used in haskellPackages.developPackage
      myModifier = drv:
        pkgs.haskell.lib.addBuildTools drv (with hsPkgs; [
          cabal-install
          replica.packages.${system}.build
          hls.packages.${system}."haskell-language-server-${compilerVersion}"
          # hls.packages.${system}."hie-bios-${compilerVersion}"
          cairo # for chart-cairo
          dhall  # for the repl
          pkgs.dhall-json  # for dhall-to-json
          glib
          hasktags
          stan
          # pkg-config
          zlib
          pkgs.dhall-lsp-server
          pkgs.stylish-haskell

          # we need the mptcp.h in mptcp-pm
          pkgs.linuxHeaders
          # alternatively we could do makeLinuxHeaders pkgs.linux_latest.dev

        #   threadscope
        ]);

      mkPackage = name:
          hsPkgs.developPackage {
            root =  pkgs.lib.cleanSource (builtins.toPath ./. + "/${name}");
            name = name;
            returnShellEnv = false;
            withHoogle = true;
            overrides = haskellOverlay;
            modifier = myModifier;
          };

    in {
      packages = {

        mptcp-pm = mkPackage "mptcp-pm";

        mptcpanalyzer = hsPkgs.developPackage {
          root = pkgs.lib.cleanSource ./mptcpanalyzer;
          name = "mptcpanalyzer";
          returnShellEnv = true;
          withHoogle = true;
          overrides = hold: hnew: (haskellOverlay hold hnew) // {
            mptcp-pm = self.packages."${system}".mptcp-pm;
          };
          modifier = myModifier;
        };
      };

      defaultPackage = self.packages.${system}.mptcpanalyzer;

      devShells = {
        mptcp-pm = self.packages.${system}.mptcp-pm.envFunc {};

        mptcpanalyzer = self.packages.${system}.mptcpanalyzer.overrideAttrs(oa: {
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
