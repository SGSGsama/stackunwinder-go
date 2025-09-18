package stackunwinder

// #include "../linker/wrapper.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func initLibs() {
	exe, _ := os.Executable()
	exeDir := path.Dir(exe)
	C.setupLibEnv(C.CString(exeDir)) // initialize the C library
	if isDebug {
		C.test_CGO(12345)
	}
}

var ProbeObjs *probes_Objects = nil

func Main() {
	var (
		targetPid     = flag.Uint("pid", 0, "target pid")
		_isDebug      = flag.Bool("d", false, "enable debug mode")
		targetSyscall = flag.String("s", "", "target syscall name,splitted by ',' ")
		targetLib     = flag.String("lib", "libc.so", "target lib to trace, e.g. libc.so ,splitted by ',' ")
		// enableStackUnwind = flag.Bool("stack", false, "enable stack unwind in eBPF program")
	)
	flag.Parse()
	setDebugMode(*_isDebug)
	initLibs()
	debug("target pid %d \n", *targetPid)

	if err := rlimit.RemoveMemlock(); err != nil { // remove kernel memory lock limit
		log.Fatal(err)
	}
	var opts *ebpf.CollectionOptions
	if isDebug {
		opts = &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel:     ebpf.LogLevelInstruction,
				LogSizeStart: 1024 * 1024, // 1MB log size
			},
		}
	} else {
		opts = nil
	}

	objs := probes_Objects{}
	if err := loadProbes_Objects(&objs, opts); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	ProbeObjs = &objs                      // save the probes objects globally
	objs.TargetPid.Set(uint32(*targetPid)) // set target pid in eBPF program
	// setStackAddrTable(int(*targetPid))     // set stack end address in eBPF program
	setTargetSyscall(strings.Split(*targetSyscall, ","))
	setTargetLib(uint32(*targetPid), strings.Split(*targetLib, ","))
	debug("self pid: %d\n", uint32(os.Getpid()))
	debug("bpf obj loaded\n")

	sysEnterTp, err := link.AttachTracing(link.TracingOptions{Program: objs.SysEnter, AttachType: ebpf.AttachTraceRawTp}) // attach to sys_enter
	if err != nil {
		log.Fatal(err)
	}
	debug("tp attached\n")
	defer sysEnterTp.Close()

	sysEnterRb, err := ringbuf.NewReader(objs.SysEnterRb)
	if err != nil {
		log.Fatal()
	}
	defer sysEnterRb.Close()

	debug("sysEnter ringbuf reader created\n")

	process, err := os.FindProcess(int(*targetPid))
	if err != nil {
		log.Fatalf("find process err: %v", err)
	}

	var sysEnterData probes_SysEnterDataNoStack
	for {
		data, err := sysEnterRb.Read()
		if err != nil {
			log.Printf("reading sysEnter err: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(data.RawSample), binary.LittleEndian, &sysEnterData); err != nil { // 这里先同步读，rb爆了后面再说
			log.Printf("reading sysEnterData err: %v", err)
			continue
		}
		// debug("stacksize %d\n", sysEnterData.StackSize)
		if !checkMemoryRange(sysEnterData.Pc) { // 这里如果不在我们关注的范围内就直接跳过就完事了
			if err := process.Signal(syscall.SIGCONT); err != nil {
				log.Printf("fail to resume process: %v", err)
			}
			continue
		}
		PrintSyscallInfo(&sysEnterData)
		debug("pc %x\n", sysEnterData.Pc)
		var tmp_ uint64
		ProbeObjs.StackBaseAddrTable.Lookup(&(sysEnterData.Tid), &tmp_) // 这里如果是主线程的话会返回0，不过无所谓了
		debug("stack_end %x\n", tmp_)
		debug("tid %d\n", sysEnterData.Tid)
		debug("sp %x\n", sysEnterData.Sp)
		var tmp C.struct_Data
		for i := 0; i < 31; i++ {
			tmp.regs[i] = C.uint64_t(sysEnterData.Regs[i])
		}
		tmp.pc = C.uint64_t(sysEnterData.Pc)
		tmp.sp = C.uint64_t(sysEnterData.Sp)
		// for i := 0; i < int(sysEnterData.StackSize); i++ {
		// tmp.stackData[i] = C.char(sysEnterData.StackData[i])
		// }
		// tmp.stackSize = C.uint64_t(sysEnterData.StackSize)
		var StackRes = C.GoString(C.unwind_Online(C.int(*targetPid), (*C.struct_Data)(unsafe.Pointer(&tmp))))
		fmt.Println(StackRes)
		fmt.Println("===================================")
		// var tidState uint32 = 0
		// ProbeObjs.probes_Maps.TidStateMap.Lookup(&(sysEnterData.Tid), &tidState)
		// if tidState == uint32(probes_TidStateSTATE_CAPTURE) {
		// 	ProbeObjs.probes_Maps.TidStateMap.Update(&(sysEnterData.Tid), uint32(probes_TidStateSTATE_RESUME), ebpf.UpdateAny)
		if err := process.Signal(syscall.SIGCONT); err != nil {
			log.Printf("fail to resume process: %v", err)
		}
		// }

	}
}
