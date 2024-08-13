#!/bin/bash

# Function to execute on interrupt
cleanup() {
    echo "Keyboard interrupt detected. Cleaning up..."
    ps -ef | grep -i './app' | grep -v grep | awk '{print "kill -9 "$2}' | sh
    ps -ef | grep -i './generate_keys' | grep -v grep | awk '{print "kill -9 "$2}' | sh
    ps -ef | grep -i './validate_result' | grep -v grep | awk '{print "kill -9 "$2}' | sh
    exit 1
}

# Set trap to catch SIGINT (Ctrl+C) and call cleanup function
trap cleanup SIGINT

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

./app --cc ../files/cc.bin --key_pub ../files/pub.bin --key_mult ../files/mult.bin --key_rot ../files/rot.bin --array ../files/in.bin --output ../files/out.bin
./validate_result