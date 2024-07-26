#!/bin/bash
rm -rf build/*
cd build
cmake ..
make
./generate_keys