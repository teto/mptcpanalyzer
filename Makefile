

TEST_FILES ?= tests/tcp.json tests/mptcp.json

# TODO should be doable via LSP/test ormolu
stylish-haskell:
	stylish-haskell

.PHONY: hlint
hlint:
	hlint

configure:
	cabal configure

build:
	cabal build

.PHONY: test
test: build $(TEST_FILES)
	# TODO run $(TEST_FILES)
	# export PATH=$(dirname $(fd -u --glob  mptcpanalyzer -tx));${PATH}
	tests/run.sh

.PHONY: gen-autocompletion
gen-autocompletion:
	cabal run mptcpanalyzer -- --bash-completion-script toto


%.json: %.dhall
	dhall-to-json --file $< --output $@

stan:
	stan

# $(TEST_FILES):
	# -v ${PWD}/build/doc/$(@F):/docs/build/html/ $(subst _,-,$(@F)) poetry run sh -c \

	# dhall-to-json --file tests/$(basename @F).dhall --output tests/$(@F).json

# gen-tests:
# 	dhall-to-json --file tests/hello.dhall --output tests/hello.json

