let
  overlay = self: prev: {
      haskell = prev.haskell // {
        packageOverrides = hnew: hold: with prev.haskell.lib;{

          ip = dontCheck hold.ip;
          bytebuild = dontCheck hold.bytebuild;

          # for newer nixpkgs (March 2020)
          # base-compat = doJailbreak (hold.base-compat);
          # time-compat = doJailbreak (hold.time-compat);
          # mptcp-pm = (overrideSrc hold.mptcp-pm {
          #   src = prev.fetchFromGitHub {
          #     owner = "teto";
          #     repo = "mptcp-pm";
          #     rev = "4087bd580dcb08919e8e3bc78ec3b25d42ee020d";
          #     sha256 = "sha256-MiXbj2G7XSRCcM0rnLrbO9L5ZFyh6Z3sPtnH+ddInI8=";
          #   };
          # });
          netlink = (overrideSrc hold.netlink {
            # src = builtins.fetchGit {
            #   # url = https://github.com/ongy/netlink-hs;
            #   url = https://github.com/teto/netlink-hs;
            # };
            src = prev.fetchFromGitHub {
              owner = "teto";
              repo = "netlink-hs";
              rev = "090a48ebdbc35171529c7db1bd420d227c19b76d";
              sha256 = "sha256-qopa1ED4Bqk185b1AXZ32BG2s80SHDSkCODyoZfnft0=";
            };
          });
        };
      };
  };

  # nixpkgsRev = "f5e8bdd07d1afaabf6b37afc5497b1e498b8046f";
  nixpkgsRev = "7cb76200088f45cd24a9aa67fd2f9657943d78a4";
  # pinned nixpkgs before cabal 3 becomes the default else hie fails
  # nixpkgs = import <nixpkgs>
  nixpkgs = import (builtins.fetchTarball {
      name = "nixos-unstable";
      url = "https://github.com/nixos/nixpkgs/archive/${nixpkgsRev}.tar.gz";
      sha256 = "12q3jy364nrcixfnd522jc9piagnc16p5b5l57mgp01lk311k7z1";
      # sha256 = "1fmwkb2wjfrpx8fis4x457vslam0x8vqlpfwqii6p9vm33dyxhzk";
  })
  {
    overlays = [ overlay]; config = {allowBroken = true;};
  };
in
  nixpkgs
