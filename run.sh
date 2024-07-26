#!/bin/bash
rm -rf build/*
cd build
cmake ..
make
./generate_keys
./app --cc cc.bin --key_public pub.bin --key_mult mult.bin --key_rot rot.bin --array in.bin --output out.bin