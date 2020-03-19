#!/bin/bash

xcrun -sdk iphoneos clang -arch arm64e -arch arm64 -dynamiclib -lc++ -framework UIKit -framework IOKit -install_name "@executable_path/jelbrekLib.dylib" -Iinclude -Ikerneldec/lzfse/ -fobjc-arc kerneldec/*.c kerneldec/*.cpp kerneldec/lzfse/*.c *.c *.m -o downloads/jelbrekLib.dylib
