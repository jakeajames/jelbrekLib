#!/bin/bash

xcrun -sdk iphoneos clang -arch arm64e -arch arm64 -dynamiclib -lc++ -framework UIKit -framework IOKit -install_name "@executable_path/jelbrekLib.dylib" -Iinclude -fobjc-arc *.c *.m *.cpp -o downloads/jelbrekLib.dylib
