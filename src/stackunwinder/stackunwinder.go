package stackunwinder

// #include "../linker/wrapper.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path"
	"stackunwinder-go/src/stackunwinder/bpfloader"
	"stackunwinder-go/src/stackunwinder/debug"
	"stackunwinder-go/src/stackunwinder/filters"
	"stackunwinder-go/src/stackunwinder/options"
	"stackunwinder-go/src/stackunwinder/utilis"
	"syscall"
	"unsafe"
)

func initLibs() {
	exe, _ := os.Executable()
	exeDir := path.Dir(exe)
	C.setupLibEnv(C.CString(exeDir)) // initialize the C library
	if debug.IsDebug {
		C.test_CGO(12345)
	}
}

func Main() {
	initLibs()
	options.InitOptions()

	bpfloader.LoadBpfObjs()
	defer bpfloader.CloseBpfObjs()
	debug.Debug("bpf obj loaded")

	bpfloader.AttachTp_sysEnter()
	defer bpfloader.CloseTp_sysEnter()
	debug.Debug("tp attached")

	bpfloader.LoadRb_forSysEnter()
	defer bpfloader.CloseRb_forSysEnter()
	debug.Debug("rb loaded")

	options.SetBpfSettings()

	process, err := os.FindProcess(int(options.TargetPid))
	if err != nil {
		log.Fatalf("find process err: %v", err)
	}

	var sysEnterData bpfloader.Probes_SysEnterDataNoStack
	for {
		data, err := bpfloader.SysEnterRb.Read()
		if err != nil {
			log.Printf("reading sysEnter err: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(data.RawSample), binary.LittleEndian, &sysEnterData); err != nil { // 这里先同步读，rb爆了后面再说
			log.Printf("reading sysEnterData err: %v", err)
			continue
		}
		// debug.Debug("stacksize %d\n", sysEnterData.StackSize)
		if !filters.CheckMemoryRange(sysEnterData.Pc) { // 这里如果不在我们关注的范围内就直接跳过就完事了
			if err := process.Signal(syscall.SIGCONT); err != nil {
				log.Printf("fail to resume process: %v", err)
			}
			continue
		}
		utilis.PrintSyscallInfo(&sysEnterData)
		debug.Debug("pc %x\n", sysEnterData.Pc)
		var tmp_ uint64
		debug.Debug("stack_end %x\n", tmp_)
		debug.Debug("tid %d\n", sysEnterData.Tid)
		debug.Debug("sp %x\n", sysEnterData.Sp)
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
		var StackRes = C.GoString(C.unwind_Online(C.int(options.TargetPid), (*C.struct_Data)(unsafe.Pointer(&tmp))))
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
