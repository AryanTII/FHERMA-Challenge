#!/bin/bash
if [ ! -d "build" ]; then
  mkdir build
fi

if [ ! -d "files" ]; then
  mkdir files
fi

if [ "$1" == "1" ]; then
    rm -rf build/*
fi

cd build

if [ "$1" == "1" ]; then
    cmake ..
fi

make

if [ "$1" == "1" ]; then
    ./generate_keys
fi

./app --cc ../files/cc.bin --key_pub ../files/pub.bin --key_mult ../files/mult.bin --key_rot ../files/rot.bin --array ../files/in.bin --idx ../files/index.bin --output ../files/out.bin
./validate_result