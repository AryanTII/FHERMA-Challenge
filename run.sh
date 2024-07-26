#!/bin/bash
rm -rf build/*
cd build
cmake ..
make

# Check if the first argument is provided and is equal to 1
if [ "$1" == "1" ]; then
    ./generate_keys
fi

./app --cc cc.bin --key_public pub.bin --key_mult mult.bin --key_rot rot.bin --array in.bin --output out.bin
./validate_result