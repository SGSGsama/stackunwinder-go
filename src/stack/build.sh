TC="/home/sgsg/ebpf/android-ndk-r27c/toolchains/llvm/prebuilt/linux-x86_64/bin"

CXX="$TC/aarch64-linux-android35-clang++"

"$CXX" -std=c++20 -O2 -shared -fPIC ./stackHelp.cpp \
-I"/home/sgsg/ebpf/libunwindstack/libunwindstack/include" \
-L"/home/sgsg/ebpf/libunwindstack/build" \
-static-libgcc -static-libstdc++ \
-lunwindstack \
-lbase \
-ldexfile_stub \
-llzma \
-lprocinfo \
-lziparchive \
-llog \
-lz \
-o stackHelp.so
