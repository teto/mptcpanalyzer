gen-completion:
	cabal run mptcp-manager -- --zsh-completion-script mptcp-path-manager > completion.zsh

lint: stylish-haskell

stylish-haskell:
	git ls-files '*.hs' | xargs -P0 -I {} sh -c "stylish-haskell -i {}"

