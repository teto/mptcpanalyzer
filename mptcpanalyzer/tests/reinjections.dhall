let Replica = https://raw.githubusercontent.com/REPLicaTest/REPLica/main/dhall/replica.dhall
let args = "--log-level Info"

in {
'analyze examples/client_2_filtered.pcapng 1 examples/server_2_filtered.pcapng 1'
  list-mptcp = Replica.Minimal::{
    command = ''
      mptcpanalyzer ${args} "analyze examples/client_2_filtered.pcapng 1 examples/server_2_filtered.pcapng 1" "quit"
    ''
    , tags = ["mptcp"]
  },
  -- map-mptcp = Replica.Minimal::{
  --   command = ''
  --     mptcpanalyzer "map-mptcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0" "quit"
  --     ''
  --   , tags = ["mptcp"]
  -- },
  -- plot-owd = Replica.Minimal::{
  --   command = ''
  --     mptcpanalyzer "plot-mptcp owd examples/client_2_filtered.pcapng 0 examples/server_2_filtered.pcapng 0" "quit"
  --   ''
  --   , tags = ["plot", "owd", "mptcp"]
  -- }
}

