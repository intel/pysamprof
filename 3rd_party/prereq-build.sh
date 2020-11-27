#!/bin/sh
set -e

PYTHON_CONFIG=${1:-`which python3-config`}
cd "`dirname $0`"
SOURCE="`pwd`"
TARGET="`pwd`/../build"
mkdir -p "$TARGET"

echo "Building libunwind"
    cd "$SOURCE/libunwind"
    ./autogen.sh
    CFLAGS="`${PYTHON_CONFIG} --cflags` -fPIC" LDFLAGS="`${PYTHON_CONFIG} --ldflags`" ./configure "--prefix=$TARGET/libunwindkit" --enable-shared=no
    make
    make install
    echo "Building libunwind succeeded"

echo "Building XED"
    cd "$SOURCE/intel-xed"
    python mfile.py --extra-flags="`${PYTHON_CONFIG} --cflags` -fPIC" --extra-linkflags="`${PYTHON_CONFIG} --ldflags`" --install-dir="$TARGET/xedkit" install
    echo "Building XED succeeded"

echo "Building protobuf"
    cd "$SOURCE/protobuf"
    ./autogen.sh
    CFLAGS="`${PYTHON_CONFIG} --cflags` -fPIC" LDFLAGS="`${PYTHON_CONFIG} --ldflags`" ./configure "--prefix=$TARGET/protobufkit"
    make
    make install
    cd "./python"
    python3 setup.py build
    echo "Building protobuf succeeded"

echo "Building protobuf-c"
    cd "$SOURCE/protobuf-c"
    ./autogen.sh
    PKG_CONFIG_PATH="$TARGET/protobufkit/lib/pkgconfig/" CFLAGS="`${PYTHON_CONFIG} --cflags` -fPIC" LDFLAGS="`${PYTHON_CONFIG} --ldflags`" ./configure "--prefix=$TARGET/protobufc-kit" --enable-shared=no
    make
    make install
    echo "Building protobuf-c succeeded"

echo "Building safestringlib"
    cd "$SOURCE/safestringlib"
    make
    echo "Building safestringlib succeeded"

exit 0

