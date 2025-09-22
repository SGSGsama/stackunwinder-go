package eventReader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"stackunwinder-go/src/stackunwinder/bpfloader"
	"stackunwinder-go/src/stackunwinder/options"
	"stackunwinder-go/src/stackunwinder/utilis"
	"syscall"
)

// 基本可以照搬sys_enter_reader ，把数据解析写一下
func Event_reader_common_uprobe() {
	process, err := os.FindProcess(int(options.TargetPid))
	if err != nil {
		fmt.Println("FindProcess error:", err)
		os.Exit(0)
	}
	var uprobeCommonData bpfloader.Probes_UprobeCommonData
	for {
		data, err := bpfloader.UprobeCommonRb.Read()
		if err != nil {
			fmt.Printf("reading sysEnterData err: %v", err)
		}
		if err := binary.Read(bytes.NewBuffer(data.RawSample), binary.LittleEndian, &uprobeCommonData); err != nil {
			fmt.Printf("reading sysEnterData err: %v\n", err)
			continue
		}
		regRead := uprobeCommonData.Mask >> 32
		strRead := uprobeCommonData.Mask & 0xFFFFFFFF
		res := "["
		strRes := ""
		strReadCount := 0
		for i := 0; i < 31; i++ {
			if regRead&(1<<i) != 0 {
				res += fmt.Sprintf("x%d: %x ,", i, uprobeCommonData.Regs[i])
				if strRead&(1<<i) != 0 && strReadCount < 8 {
					strRes += fmt.Sprintf("x%d:", i) + utilis.PrintUnkBytes(uprobeCommonData.Buf[strRead][:], 64, "") + "\n"
					strReadCount++
				}
			}
		}
		if res[len(res)-1] == ',' {
			res = res[:len(res)-1]
		}
		res += "]"
		fmt.Printf("[pc: %x sp: %x tid: %d] %s\n", uprobeCommonData.Pc, uprobeCommonData.Sp, uprobeCommonData.Tid, res)
		if strRes != "" {
			fmt.Print(strRes)
		}
		if options.EnableStackUnwind {
			var StackRes = utilis.GetStackUnwindGoWrapper(&uprobeCommonData, int(options.TargetPid))
			fmt.Println(StackRes)
		}
		if err := process.Signal(syscall.SIGCONT); err != nil {
			fmt.Printf("fail to resume process: %v", err)
		}
	}
}
