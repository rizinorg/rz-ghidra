mkdir -p build && cd build
cmake ../ -G Ninja \
    -DCMAKE_C_COMPILER=cl \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX;$INSTALL_PREFIX/include/libr;$INSTALL_PREFIX/include/libr/sdb;$QT64PATH" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
    -DBUILD_CUTTER_PLUGIN=ON \
    -DCUTTER_SOURCE_DIR="$CUTTER_PATH" \
    -DBUILD_SLEIGH_PLUGIN=ON
ninja
ninja install
