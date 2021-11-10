

TEST_FILES ?= tests/tcp.json tests/mptcp.json

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

.PHONY: test
test: build $(TEST_FILES)
	# TODO run $(TEST_FILES)
	# export PATH=$(dirname $(fd -u --glob  mptcpanalyzer -tx));${PATH}
	tests/run.sh

# regen golden tests
test-update: build $(TEST_FILES)
	# TODO run $(TEST_FILES)
	# export PATH=$(dirname $(fd -u --glob  mptcpanalyzer -tx));${PATH}
	tests/run.sh

.PHONY: gen-autocompletion
gen-completion: build
	cabal run mptcpanalyzer -- --bash-completion-script mptcpanalyzer > completion.sh
	cabal run mptcpanalyzer -- --zsh-completion-script mptcpanalyzer > _mptcpanalyzer


%.json: %.dhall
	dhall-to-json --file $< --output $@

stan:
	stan

# $(TEST_FILES):
	# -v ${PWD}/build/doc/$(@F):/docs/build/html/ $(subst _,-,$(@F)) poetry run sh -c \

	# dhall-to-json --file tests/$(basename @F).dhall --output tests/$(@F).json

# gen-tests:
# 	dhall-to-json --file tests/hello.dhall --output tests/hello.json

