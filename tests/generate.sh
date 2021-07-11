


plot tcp examples/client_2_filtered.pcapng 0 tcpSeq

plot mptcp examples/client_2_filtered.pcapng 0 tcpSeq


-- for reinjections
analyze examples/client_2_cleaned.pcapng 0 examples/server_2_cleaned.pcapng 0


plot owd examples/client_2_cleaned.pcapng examples/server_2_cleaned.pcapng 0 0 --display
