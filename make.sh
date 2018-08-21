#!/bin/bash

rm jelbrekLib.dylib 2> /dev/null
xcrun -sdk iphoneos clang -c -arch arm64 -Iinclude *.c *.m *.cpp && ar rcu jelbrekLib.a *.o && rm *.o

