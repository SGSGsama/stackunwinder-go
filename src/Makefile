HOST_OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH ?= $(shell uname -m)
ANDROID_NDK_ROOT ?= $(error ANDROID_NDK_ROOT not set)

# 优先尝试原生架构，fallback到x86_64
NATIVE_TC := $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/$(HOST_OS)-$(RAW_HOST_ARCH)/bin
FALLBACK_TC := $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/$(HOST_OS)-x86_64/bin
TC := $(shell if [ -d "$(NATIVE_TC)" ]; then echo "$(NATIVE_TC)"; else echo "$(FALLBACK_TC)"; fi)

CC:=$(TC)/aarch64-linux-android$(TARGET_API)-clang
CXX:=$(TC)/aarch64-linux-android$(TARGET_API)-clang++
AR:=$(TC)/llvm-ar

APP:=stackunwinder-go

stack_src:= $(wildcard stack/*.cpp)

LIBUNWINDSTACK_ROOT ?= $(error LIBUNWINDSTACK_ROOT not set)
ANDROID_SYSROOT:= $(TC)/../sysroot
stack_LDPATH:= -L$(LIBUNWINDSTACK_ROOT)/build -L$(ANDROID_SYSROOT)/usr/lib
stack_LDFLAGS:= $(stack_LDPATH) -lunwindstack -lbase -ldexfile_stub -llzma -lprocinfo -lziparchive -llog -lz
stack_INCLUDES:= -I$(ANDROID_SYSROOT)/usr/include/aarch64-linux-android -I$(ANDROID_SYSROOT)/usr/include -I$(LIBUNWINDSTACK_ROOT)/include
stack_CXXFLAGS:= -std=c++20 -O2 -Wall -fPIC 

app: $(APP)


stackHelp.so: $(stack_src)
	$(CXX) $(stack_CXXFLAGS) -shared -o $@ $^ $(stack_LDFLAGS) $(stack_INCLUDES)


.PHONY: clean
clean:
	rm -f stackHelp.so
	rm -f $(wildcard stackunwinder/bpfloader/probes__bpfel.*)
	rm -f $(APP)
	rm -f linker/libwrapper.a
	rm -f linker/wrapper.o

BPF_CLANG:=$(TC)/aarch64-linux-android$(TARGET_API)-clang
BPF_CFLAGS:=-O2 -g -target bpf

BPF_SKEL:=stackunwinder/bpfloader/probes__bpfel.go

$(BPF_SKEL): $(wildcard kernel/*.c)
	@echo "=== Generating BPF Go bindings ==="
	@echo "Using BPF_CLANG: $(BPF_CLANG)"
	@echo "Using BPF_CFLAGS: $(BPF_CFLAGS)"
	cd stackunwinder && \
	go run github.com/cilium/ebpf/cmd/bpf2go \
	-go-package bpfloader \
	-target bpfel \
	-cc "$(BPF_CLANG)" \
	-cflags "$(BPF_CFLAGS)" \
	-type sysEnterData_noStack \
	-type uprobeCommonData \
	Probes_ ../kernel/probes.c
	mv stackunwinder/probes_* stackunwinder/bpfloader/
	cd ..
	@echo "=== BPF Go bindings generated successfully ==="

WRAPPER_CFLAGS:=-I./linker -O2 -c -g -Wall -fPIC

linker/wrapper.o: linker/wrapper.c linker/wrapper.h
	$(CC) $(WRAPPER_CFLAGS) -c linker/wrapper.c -o linker/wrapper.o
linker/libwrapper.a: linker/wrapper.o
	$(AR) rcs $@ linker/wrapper.o

GONEED:= main.go $(wildcard stackunwinder/*.go) $(wildcard stackunwinder/*/*.go)


$(APP): linker/libwrapper.a $(GONEED) $(BPF_SKEL) stackHelp.so 
	@echo [include settings]  $(stack_INCLUDES)
	@echo [ld settings]  $(stack_LDFLAGS)
	CGO_ENABLED=1 \
	CC=$(CC) \
	CXX=$(CXX) \
	CGO_CFLAGS="-I./linker" \
	CGO_LDFLAGS="-L./linker -lwrapper" \
	GOOS=android \
	GOARCH=arm64 \
	go build  -o $@ .
	cp $(APP) ..


# 	CGO_CFLAGS="-I./linker" 
# 	CGO_LDFLAGS="-L./linker" 