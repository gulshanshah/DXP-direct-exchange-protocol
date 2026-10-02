#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

CXX=${CXX:-g++}
MODE=${1:-release}

FLAGS=(-std=c++17 -Wall -Wextra -pthread)
LDFLAGS=()
if [[ "$MODE" == "asan" ]]; then
    FLAGS+=(-O1 -g -fsanitize=address,undefined)
    LDFLAGS+=(-fsanitize=address,undefined)
else
    FLAGS+=(-O2)
fi

SRC="DXP DXP_AES DXP_CRC DXP_SHA256 DXP_crypto DXP_keys DXP_packet DXP_process DXP_receive DXP_transmit DXP_stream DXP_link"
HEADERS="DXP.h DXP_packet.h DXP_process.h DXP_link.h DXP_transport.h DXP_stream.h DXP_transmit.h DXP_receive.h DXP_keys.h"

mkdir -p build/lib
rm -f build/*.o

for f in $SRC; do
    "$CXX" "${FLAGS[@]}" -c "$f.cpp" -o "build/$f.o"
done

ar rcs build/lib/libdxp.a build/*.o

"$CXX" "${FLAGS[@]}" demo.cpp build/lib/libdxp.a -o build/demo "${LDFLAGS[@]}"
./build/demo

rm -rf build/include build/example
mkdir -p build/include build/example
for h in $HEADERS; do
    cp "$h" build/include/
done
cp example.cpp build/example/

"$CXX" "${FLAGS[@]}" -Ibuild/include build/example/example.cpp build/lib/libdxp.a \
    -o build/example/example "${LDFLAGS[@]}"
./build/example/example

echo
echo "Library package ready: build/include, build/lib, build/example"
