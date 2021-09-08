#!/bin/sh

RUNNER="cabal run mptcpanalyzer"
$RUNNER plot examples/client_2_filtered.pcapng 0
