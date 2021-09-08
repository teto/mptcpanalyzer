#!/bin/sh

set -x
exe=$(cabal list-bin exe:mptcpanalyzer)
PATH="$(dirname $exe):$PATH"

# see https://github.com/berewt/REPLica/issues/45
replica run tests/tcp.json
replica run tests/mptcp.json
