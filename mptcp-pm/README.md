[![Hackage][hk-img]][hk]

This is a userspace path manager for the [linux multipath TCP
kernel][mptcp-fork], starting from version v0.95.
It now also supports the upstream linux kernel.

This allows to monitor MPTCP connections and control what subflows to create and
with a custom kernel it can even set specific values for the congestion windows.


# Compilation

For now we need a custom version of netlink
With a custom netlink and kernel
Compile the custom netlink library with
```
$ cabal configure 
```
You may need some headers as well (NOTE: reference cabal.project instead):
```
$ cabal configure --extra-include-dirs=~/mptcp/build/usr/include
# or on nix you can also pass $(nix-build -A linuxHeaders)/include
# e.g., `cabal build --extra-include-dirs=/nix/store/3kag193bcwcslzz83chy93ryjv218rbp-linux-headers-5.14/include`
```

# Usage

The netlink module asks for `GENL_ADMIN_PERM` which requires the `CAP_NET_ADMIN` privilege.
You can assign this privilege via:

```
res=$(cabal list-bin exe:mptcp-manager)
sudo setcap cap_net_admin+ep "$res"
```

Enter the development shell and start the daemon:

```
$ nix develop
$ cabal run mptcp-manager
```

# TODO
- remove the need for MptcpSocket everywhere: it's just needed to write the
header, which could be added/modifier later instead ! (to increase purity in the
    library)
- we need to better keep track of subflow status (established vs WIP) ?
- pass local/server IPs as commands to the PM ?
- generate completion scripts via --zsh-completion-script


# Acknowledgements

This work is sponsored by [NGI][ngi].

[hk-img]: https://img.shields.io/hackage/v/mptcp-pm.svg?logo=haskell
[hk]: https://hackage.haskell.org/package/mptcp-pm
[mptcp-fork]: http://multipath-tcp.org/
[ngi]: https://www.ngi.eu/
