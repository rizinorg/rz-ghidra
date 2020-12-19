#!/bin/bash

mkdir -p build && cd build || exit 1
cmake ../ -G Ninja \
    -DCMAKE_C_COMPILER=cl \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX;$INSTALL_PREFIX/include/librz;$INSTALL_PREFIX/include/librz/sdb" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
    -DBUILD_SLEIGH_PLUGIN=OFF || exit 1
ninja || exit 1
ninja install || exit 1
