<!-- BEGIN-MARKDOWN-TOC -->
* [Presentation](#presentation)
* [Installation](#installation)
* [Help](#faq)
* [Related tools](#related_tools)

<!-- END-MARKDOWN-TOC -->


Presentation
===

Mptcpanalyzer is a tool conceived to help with MPTCP pcap analysis (as [mptcptrace] for instance).

It accepts packet capture files (\*.pcap) as inputs and from there you can:

- list MPTCP connections
- compute statistics on a specific MPTCP connection (list of subflows, reinjections, subflow actual contributions...)
- export a CSV file with MPTCP fields
- plot one way delays
- ...

Commands are self documented with autocompletion.
The interpreter with autocompletion that can generate & display plots such as the following:

```
cabal configure --enable-profiling
cabal run mptcpanalyzer "load-pcap examples/client_2_filtered.pcapng"  -- +RTS
-xc
```

# Installation

You will need a wireshark version __>= 3.0.0__ .
Install zsh
--zsh-completion-script


# How to use
`cabal run mptcpanalyzer`
`plot --display tcp examples/client_2_filtered.pcapng 0 tcpseq`
```
mptcpanalyzer "map-tcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0"
mptcpanalyzer "load-pcap examples/client_2_filtered.pcapng"
```

I use [vd](visidata).

# How to develop/contribute

See [CONTRIBUTING](./CONTRIBUTING.md).

## Dependencies

- [polysemy](polysemy) to handle effects
- [Frames](frames) to analyze data
- [haskell-chart](haskell-chart) with the svg backend
- [wireshark](wireshark-mptcp) to convert packet captures (.pcapng) to csv files.



# Roadmap

- improve caching
- improve autocompletion
- live statistics/plotting
- plugins ?
- ability to leverage the API in ihaskell ?

# Related tools

Similar software:

| Tool             | Description                                                                       |
|------------------------|-------------------------------------------------------------------------------|
| [mptcptrace]             | C based: [an example](http://blog.multipath-tcp.org/blog/html/2015/02/02/mptcptrace_demo.html)                                               |
| [mptcpplot]       | C based developed at NASA: [generated output example](https://roland.grc.nasa.gov/~jishac/mptcpplot/)                                                 |


# Acknowledgements

This project is founded by ![NGI pointer](img/ngi_logo.png).

[mptcptrace]: https://bitbucket.org/bhesmans/mptcptrace
[mptcpplot]: https://github.com/nasa/multipath-tcp-tools/
[hk-img]: https://img.shields.io/hackage/v/mptcpanalyzer.svg?logo=haskell
[hk]: https://hackage.haskell.org/package/mptcpanalyzer
[replica]: https://github.com/berewt/REPLica
wireshark-mptcp: https://www.wireshark.org/docs/dfref/m/mptcp.html
polysemy: https://hackage.haskell.org/package/polysemy
visidata: https://www.visidata.org/
diagrams: https://hackage.haskell.org/package/diagrams
frames: https://hackage.haskell.org/package/Frames
shelltestrunner: https://github.com/simonmichael/shelltestrunner
