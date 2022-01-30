
# TODO should be doable via LSP/test ormolu
lint: stylish-haskell

stylish-haskell:
	git ls-files '*.hs' | xargs -P0 -I {} sh -c "stylish-haskell -i {}"

.PHONY: hlint
hlint:
	hlint

configure:
	cabal configure

build:
	cabal build

stan:
	stan
