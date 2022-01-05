Presentation
===

This repository contains software for multipath TCP:
- [mptcp](./mptcp): basic haskell library used by the other projects
- [mptcp-pm](./mptcp-pm): a userspace path manager
- [mptcpanalyzer](./mptcpanalyzer): a tool to help with MPTCP pcap analysis

Mptcpanalyzer accepts packet capture files (\*.pcap) as inputs and from there you can:

- list MPTCP connections
- compute statistics on a specific MPTCP connection (list of subflows, reinjections, subflow actual contributions...)
- export a CSV file with MPTCP fields
- plot one way delays
- ...

See its README for more info.

See [this blog](http://teto.github.io/tags/mptcp.html) for more tutorials about mptcpanalyzer.

# Acknowledgements

This project is founded by ![NGI pointer](mptcpanalyzer/img/ngi_logo.png).
