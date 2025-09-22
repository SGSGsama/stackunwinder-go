package eventReader

// #include "../../linker/wrapper.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"stackunwinder-go/src/stackunwinder/bpfloader"
	"stackunwinder-go/src/stackunwinder/debug"
	"stackunwinder-go/src/stackunwinder/filters"
	"stackunwinder-go/src/stackunwinder/options"
	"stackunwinder-go/src/stackunwinder/utilis"
	"syscall"
)

// 这里似乎可以直接用协程？对于目标程序而言每次触发检测点都会断下，所以这里其实在信号上不会有异步问题，因此不用对信号发送机制上锁
// 实际上似乎变成了多线程轮询的效果，效率肯定不如stackplz
func Event_reader_sys_enter() {
	process, err := os.FindProcess(int(options.TargetPid))
	if err != nil {
		fmt.Println("find process err: ", err)
		os.Exit(0)
	}

	var sysEnterData bpfloader.Probes_SysEnterDataNoStack
	for {
		data, err := bpfloader.SysEnterRb.Read()
		if err != nil {
			fmt.Printf("reading sysEnter err: %v\n", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(data.RawSample), binary.LittleEndian, &sysEnterData); err != nil { // 这里先同步读，rb爆了后面再说
			fmt.Printf("reading sysEnterData err: %v\n", err)
			continue
		}
		if !filters.CheckMemoryRange(sysEnterData.Pc) { // 这里如果不在我们关注的范围内就直接跳过就完事了
			if err := process.Signal(syscall.SIGCONT); err != nil {
				fmt.Printf("fail to resume process: %v\n", err)
			}
			continue
		}
		utilis.PrintSyscallInfo(&sysEnterData)
		debug.Debug("pc %x\n", sysEnterData.Pc)
		var tmp_ uint64
		debug.Debug("stack_end %x\n", tmp_)
		debug.Debug("tid %d\n", sysEnterData.Tid)
		debug.Debug("sp %x\n", sysEnterData.Sp)
		if options.EnableStackUnwind {
			var StackRes = utilis.GetStackUnwindGoWrapper(&sysEnterData, int(options.TargetPid))
			fmt.Println(StackRes)
		}
		fmt.Println("===================================")
		if err := process.Signal(syscall.SIGCONT); err != nil {
			fmt.Printf("fail to resume process: %v", err)
		}
	}
}
