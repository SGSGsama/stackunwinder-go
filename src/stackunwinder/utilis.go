package stackunwinder

import (
	"fmt"
	"log"
	"os"
	"unicode"

	"github.com/cilium/ebpf"
)

func getSyscallId(constID *ebpf.Variable) uint64 {
	var id uint32
	constID.Get(&id) // 从bpf头文件中的表获取syscallId，保证统一性
	// log.Printf("%d %d\n",constID.Size(),id);
	return uint64(id)
}
func printUnkBytes(data []uint8, len int, tag string) {
	// 这里如果是可打印字符就打印字符，不然就打印hex
	debug("printBytes: len: %d\n", len)
	len = min(len, 64) // 先设置最大打印64个byte，后续添加上限调整功能
	fmt.Printf("%s ", tag)
	for i := 0; i < len; i++ {
		if unicode.IsPrint(rune(data[i])) {
			fmt.Printf("%c", data[i])
		} else {
			fmt.Printf("\\x%02x", data[i])
		}
	}
	fmt.Println()
}

// func setStackAddrTable(pid int) {
// 	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)) // 直接读maps获取内存布局
// 	if err != nil {
// 		log.Fatalln("Error reading maps file:", err)
// 	}
// 	lines := strings.Split(string(maps), "\n")
// 	for _, line := range lines {
// 		parts := strings.Fields(line)
// 		debug("parts: %v\n", parts)
// 		if len(parts) < 6 {
// 			continue
// 		}
// 		memoryName := parts[5]                       // 提取段名
// 		if strings.Contains(memoryName, "[stack]") { //处理主线程
// 			memoryRangeStr := strings.Split(parts[0], "-")
// 			debug("%v\n", memoryRangeStr)
// 			stackEnd, err := strconv.ParseUint(memoryRangeStr[1], 16, 64)
// 			if err != nil {
// 				log.Fatalln("Error parsing stack end:", err)
// 			}
// 			debug("set main thread stackend to %x\n", stackEnd)
// 			var __tidmain uint32 = 0
// 			ProbeObjs.probes_Maps.StackBaseAddrTable.Put(&__tidmain, &stackEnd) // 主线程的栈地址放在0位，主要没法提前知道主线程tid
// 			if isDebug {
// 				var __tmp uint64
// 				ProbeObjs.probes_Maps.StackBaseAddrTable.Lookup(&__tidmain, &__tmp)
// 				debug("set stackend %x \n", __tmp)
// 			}
// 		} else if strings.Contains(memoryName, "stack_and_tls") && "rw-p" == parts[1] { // 处理子线程，这里只要有读写权限的，还有一个同名但无权限的是保护段，不是我们要的
// 			tidStr := strings.Split(memoryName, ":")[2][0 : len(strings.Split(memoryName, ":")[2])-1] // 把tid抠出来
// 			if tidStr == "main" {                                                                     // 记号为main的栈不知道是什么东西，先跳过
// 				continue
// 			}

// 			_tid, err := strconv.ParseUint(tidStr, 10, 32)
// 			tid := uint32(_tid)
// 			if err != nil {
// 				log.Fatalln("Error parsing tid:", err)
// 			}

// 			memoryRangeStr := strings.Split(parts[0], "-")
// 			debug("%v\n", memoryRangeStr)
// 			stackEnd, err := strconv.ParseUint(memoryRangeStr[1], 16, 64)
// 			if err != nil {
// 				log.Fatalln("Error parsing stack end:", err)
// 			}
// 			debug("set thread %d stackend to %x\n", tid, stackEnd)
// 			ProbeObjs.probes_Maps.StackBaseAddrTable.Put(&tid, &stackEnd)
// 			if isDebug {
// 				var __tmp uint64
// 				ProbeObjs.probes_Maps.StackBaseAddrTable.Lookup(&tid, &__tmp)
// 				debug("set stackend %x \n", __tmp)
// 			}
// 		}
// 	}
// }

func PrintSyscallInfo(data *probes_SysEnterDataNoStack) { // 几个常用的syscall手动设置下打印格式
	fmt.Printf("[pc: %x sp: %x tid: %d]", data.Pc, data.Sp, data.Tid)
	switch data.SyscallId {
	case getSyscallId(ProbeObjs.probes_Variables.OPENAT):
		fmt.Printf("[openat] dfd: %d, filename(addr: %x): %s, flags: 0x%x, mode: 0x%x\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeObjs.probes_Variables.READ):
		fmt.Printf("[read] fd: %d, buf(addr: %x), count: %d\n", data.Regs[0], data.Regs[1], data.Regs[2])
		printUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[read] buf:")
	case getSyscallId(ProbeObjs.probes_Variables.WRITE):
		fmt.Printf("[write] fd: %d, buf(addr: %x), count: %d\n", data.Regs[0], data.Regs[1], data.Regs[2])
		printUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[write] buf:")
	case getSyscallId(ProbeObjs.probes_Variables.PREAD64):
		fmt.Printf("[pread64] fd: %d, buf(addr: %x), count: %d, offset: 0x%x\n", data.Regs[0], data.Regs[1], data.Regs[2], data.Regs[3])
		printUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[pread64] buf:")
	case getSyscallId(ProbeObjs.probes_Variables.PWRITE64):
		fmt.Printf("[pwrite64] fd: %d, buf(addr: %x), count: %d, offset: 0x%x\n", data.Regs[0], data.Regs[1], data.Regs[2], data.Regs[3])
		printUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[pwrite64] buf:")
	case getSyscallId(ProbeObjs.probes_Variables.READLINKAT):
		fmt.Printf("[readlinkat] dfd: %d, pathname(addr: %x): %s, buf(addr: %x), buflen: %d\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeObjs.probes_Variables.NEWFSTATAT):
		fmt.Printf("[newfstatat] dfd: %d, pathname(addr: %x): %s, statbuf(addr: %x), flags: 0x%x\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeObjs.probes_Variables.PTRACE):
		commPath := fmt.Sprintf("/proc/%d/cmdline", data.Regs[1])
		tmp, err := os.ReadFile(commPath)
		var comm string
		if err != nil {
			comm = "fail to read comm"
		} else {
			comm = string(tmp)
		}
		fmt.Printf("[ptrace] request: %d, pid: %d [%s], addr: %x, data: %x\n", data.Regs[0], data.Regs[1], comm, data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeObjs.probes_Variables.CLONE):
		fmt.Printf("[clone] flags: 0x%x, newsp: %x\n", data.Regs[0], data.Regs[1])
	case getSyscallId(ProbeObjs.probes_Variables.EXECVE):
		fmt.Printf("[execve] filename(addr: %x): %s\n", data.Regs[0], data.ArgBuf[0])
	case getSyscallId(ProbeObjs.probes_Variables.GETRANDOM):
		fmt.Printf("[getrandom] buf(addr: %x), buflen: %d, flags: 0x%x\n", data.Regs[0], data.Regs[1], data.Regs[2])
	case getSyscallId(ProbeObjs.probes_Variables.EXECVEAT):
		fmt.Printf("[execveat] dfd: %d, filename(addr: %x): %s, flags: 0x%x\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[4])
	case getSyscallId(ProbeObjs.probes_Variables.CLONE3):
		fmt.Printf("[clone3] uargs(addr: %x), size: %d\n", data.Regs[0], data.Regs[1])
	case getSyscallId(ProbeObjs.probes_Variables.OPENAT2):
		fmt.Printf("[openat2] dfd: %d, filename(addr: %x): %s\n", data.Regs[0], data.Regs[1], data.ArgBuf[0])
	default:
		fmt.Printf("[syscall] id: 0x%x, x0: 0x%x, x1: 0x%x, x2: 0x%x, x3: 0x%x, x4: 0x%x, x5: 0x%x\n", data.SyscallId, data.Regs[0], data.Regs[1], data.Regs[2], data.Regs[3], data.Regs[4], data.Regs[5])
	}
}

var isDebug bool = false

func debug(format string, args ...interface{}) {
	if isDebug {
		log.Printf(format, args...)
	}
}
func setDebugMode(_isDebug bool) {
	isDebug = _isDebug
	if isDebug {
		os.Setenv("STACKUNWINDER_DEBUG", "1") // set environment variable for debug mode
	} else {
		os.Setenv("STACKUNWINDER_DEBUG", "0")
	}
}
