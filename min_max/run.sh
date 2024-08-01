#!/bin/bash
if [ ! -d "build" ]; then
  mkdir build
fi
if [ ! -d "files" ]; then
  mkdir files
fi

rm -rf build/*
cd build
cmake ..
make

# Check if the first argument is provided and is equal to 1
if [ "$1" == "1" ]; then
    ./generate_keys
fi

./app --cc ../files/cc.bin --key_public ../files/pub.bin --key_mult ../files/mult.bin --key_rot ../files/rot.bin --array ../files/in.bin --output ../files/out.bin
./validate_result