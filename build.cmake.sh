#!/bin/bash
mkdir -p build
pushd build
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
cmake ..
cmake --build . --target configurator
pushd ext
pushd secp256k1
make
popd
popd
elif [[ "$OSTYPE" == "darwin"* ]]; then
cmake ..
pushd ext
pushd secp256k1
make
popd
popd
elif [[ "$OSTYPE" == "msys" ]]; then
cmake .. --fresh
fi
sleep 1
cmake --build .
popd
exit

