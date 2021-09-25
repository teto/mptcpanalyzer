let Replica = ./Replica.dhall

let lib = ./lib.dhall

in {

  list-mptcp = Replica.Test::{
    command = lib.wrapCmd [ "load-pcap examples/client_2_filtered.pcapng", "tcp-summary --full 0"]
    , tags = ["mptcp"]
  },
  map-mptcp = Replica.Test::{
    command = lib.wrapCmd [
      "map-mptcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0"
    ]
    , tags = ["mptcp"]
  },
  plot-owd = Replica.Test::{
    command = ''
      mptcpanalyzer "plot-mptcp owd examples/client_2_filtered.pcapng 0 examples/server_2_filtered.pcapng 0" "quit"
    ''
    , tags = ["plot", "owd", "mptcp"]
  }
}
