
# How to develop ?

First of all patches welcome.

Enter the nix shell then run your typical cabal commands:
```
$ nix develop
$ cabal build
```
Note that the flake

## How to debug splices ?

`-ddump-splices -ddump-to-file -dth-dec-file`


# How to contribute ?



## Run the tests

Tests are run via [REPLica]. They are written in tests/*.dhall and converted to
json.
```
make tests
```

```
make test-integration
```

To run tests
```sh
$ replica run tests/tcp.json
```

To regenerate the tests:
```sh
make tests/tcp.json  # generates tcp.json from its tests/tcp.dhall spec
$ replica run -i tests/tcp.json  # -i interactive
```

