#!/bin/bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
rm -rf build/*
cd build
cmake ..
make
sort