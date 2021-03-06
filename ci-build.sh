#!/bin/bash -xe

python3 --version
py.test --version
python3 -mpycodestyle --version

# Target directory for all build files
BUILD=${1:-ci-build}
rm -rf ${BUILD}/
mkdir -p $BUILD

# TODO check mypy as well
python3 -mpycodestyle --ignore E501,E741,E305 i3pystatus tests

# Check that the setup.py script works
rm -rf ${BUILD}/test-install ${BUILD}/test-install-bin
mkdir ${BUILD}/test-install ${BUILD}/test-install-bin
PYTHONPATH=${BUILD}/test-install python3 setup.py --quiet install --install-lib ${BUILD}/test-install --install-scripts ${BUILD}/test-install-bin

test -f ${BUILD}/test-install-bin/i3pystatus
test -f ${BUILD}/test-install-bin/i3pystatus-setting-util


# run tests
PYTHONPATH=${BUILD}/test-install py.test -q --junitxml ${BUILD}/testlog.xml tests

# mp plot owd_tcp examples/node0.pcap examples/node1.pcap 0 --display --verbose-debug

# Check that the docs build w/o warnings (-W flag)
sphinx-build -Nq -b html -W docs ${BUILD}/docs/
