let Replica = ./Replica.dhall

let Test = Replica.Test

-- let args = "--log-level Info"
let lib = ./lib.dhall
in {

  list-tcp = Test::{
    command = lib.wrapCmd [
      "load-pcap examples/client_2_filtered.pcapng"
      , "tcp-summary --full 0"
    ]
    , tags = [ "tcp" ]
  },
  map-tcp = Test::{
    command = ''
      mptcpanalyzer "map-tcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0" "quit"
      ''
    , tags = [ "tcp" ]
  }
}

