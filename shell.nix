# from https://github.com/NixOS/nixpkgs/blob/master/doc/languages-frameworks/haskell.section.md
{
  nixpkgs ? import ./pinned_nixpkgs.nix
  # nixpkgs ? import <nixpkgs> {}
  # , compilerName ? "ghc8101" # not supported yet
  , compilerName ? "ghc884"
}:

let
  compiler = pkgs.haskell.packages."${compilerName}";
  pkgs = nixpkgs.pkgs;

  hsEnv = pkgs.haskellPackages.ghcWithPackages(hs: [
    # hs.cairo
    hs.diagrams
  ]);
  my_pkg = (import ./. { inherit compiler; } );
in
    pkgs.mkShell {
    name = "quantum";
    buildInputs = with pkgs; [
      # cairo
      glib
      hsEnv
      pkg-config
      zlib
      zlib.dev
      haskellPackages.cabal-install
      haskellPackages.ghcide
      haskellPackages.stylish-haskell
      haskellPackages.hlint
      # haskellPackages.stan  # broken
    ];
  }

  # (my_pkg.envFunc { withHoogle = true; }).overrideAttrs (oa: {
  #   nativeBuildInputs = oa.nativeBuildInputs ++ (with pkgs; [
  #     haskellPackages.ghcide
  #     haskellPackages.cabal-install
  #     haskellPackages.hasktags
  #     haskellPackages.hlint
  #     # haskellPackages.nvim-hs-ghcid # too old, won't support nvim-hs-contrib 2
  #     # haskellPackages.gutenhasktags  # taken from my overlay
  #     # haskellPackages.haskdogs # seems to build on hasktags/ recursively import things
  #   ]);

  # # export HIE_HOOGLE_DATABASE=$NIX_GHC_DOCDIR as DOCDIR doesn't exist it won't work
  # # shellHook = "eval $(grep export ${ghc}/bin/ghc)";
  # # echo "importing a custom nvim ${my_nvim}"
  # # export PATH="${my_nvim}/bin:$PATH"
  # # --package-db /home/teto/netlink-hs/dist/package.conf.inplace
  # # --package-db /home/teto/mptcppm/dist/package.conf.inplace
  # shellHook = ''
  #   # check if it's still needed ?
  #   export HIE_HOOGLE_DATABASE="$NIX_GHC_LIBDIR/../../share/doc/hoogle/index.html"
  # '';
  # })
