#!/bin/bash

mkdir -p build && cd build || exit 1
cmake ../ -G Ninja \
    -DCMAKE_C_COMPILER=cl \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX;$INSTALL_PREFIX/include/libr;$INSTALL_PREFIX/include/libr/sdb" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" || exit 1
ninja || exit 1
ninja install || exit 1
