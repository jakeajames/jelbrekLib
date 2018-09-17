#!/bin/bash

xcrun -sdk iphoneos clang -c -arch arm64 -Iinclude -fobjc-arc *.c *.m *.cpp && ar rcu downloads/jelbrekLib.a *.o && rm *.o

