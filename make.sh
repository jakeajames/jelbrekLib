#!/bin/bash

rm jelbrekLib.dylib 2> /dev/null

xcrun -sdk iphoneos clang -c -arch arm64 -Iinclude *.c *.m *.cpp &&
#xcrun -sdk iphoneos cc -dynamiclib -arch arm64 -framework IOKit -framework Foundation -install_name "@executable_path/jelbrekLib.dylib" -lstdc++ -Iinclude -o jelbrekLib.dylib *.c *.m *.cpp
#ldid -S jelbrekLib.dylib

#cd libs
#for i in *.a
#do
#    mkdir "$i-"
#    cd "$i-"
#    ar -x ../$i
#    cd ..
#done
#cd ..

ar rcu jelbrekLib.a *.o && #libs/*.a-/* libs/*.tbd

#rm -rf libs/*.a-

rm *.o
