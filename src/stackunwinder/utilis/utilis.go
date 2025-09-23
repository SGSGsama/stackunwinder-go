package utilis

// #include "../../linker/wrapper.h"
import "C"
import (
	"fmt"
	"os"
	"stackunwinder-go/src/stackunwinder/bpfloader"
	"stackunwinder-go/src/stackunwinder/debug"
	"unicode"
	"unsafe"

	"github.com/cilium/ebpf"
)

func getSyscallId(constID *ebpf.Variable) uint64 {
	var id uint32
	constID.Get(&id) // 从bpf头文件中的表获取syscallId，保证统一性
	// log.Printf("%d %d\n",constID.Size(),id);
	return uint64(id)
}
func PrintUnkBytes(data []uint8, len int, tag string) string {
	// 这里如果是可打印字符就打印字符，不然就打印hex
	res := ""
	debug.Debug("printBytes: len: %d\n", len)
	len = min(len, 64) // 先设置最大打印64个byte，后续添加上限调整功能
	res += fmt.Sprintf("%s ", tag)
	for i := 0; i < len; i++ {
		if unicode.IsPrint(rune(data[i])) {
			res += fmt.Sprintf("%c", data[i])
		} else {
			res += fmt.Sprintf("\\x%02x", data[i])
		}
	}
	return res
}

func PrintSyscallInfo(data *bpfloader.Probes_SysEnterDataNoStack) { // 几个常用的syscall手动设置下打印格式
	ProbeVar := bpfloader.BpfVar

	fmt.Printf("[pc: %x sp: %x tid: %d]", data.Pc, data.Sp, data.Tid)
	switch data.SyscallId {
	case getSyscallId(ProbeVar.OPENAT):
		fmt.Printf("[openat] dfd: %d, filename(addr: %x): %s, flags: 0x%x, mode: 0x%x\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeVar.READ):
		fmt.Printf("[read] fd: %d, buf(addr: %x), count: %d\n", data.Regs[0], data.Regs[1], data.Regs[2])
		fmt.Println(PrintUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[read] buf:"))
	case getSyscallId(ProbeVar.WRITE):
		fmt.Printf("[write] fd: %d, buf(addr: %x), count: %d\n", data.Regs[0], data.Regs[1], data.Regs[2])
		fmt.Println(PrintUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[write] buf:"))
	case getSyscallId(ProbeVar.PREAD64):
		fmt.Printf("[pread64] fd: %d, buf(addr: %x), count: %d, offset: 0x%x\n", data.Regs[0], data.Regs[1], data.Regs[2], data.Regs[3])
		fmt.Println(PrintUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[pread64] buf:"))
	case getSyscallId(ProbeVar.PWRITE64):
		fmt.Printf("[pwrite64] fd: %d, buf(addr: %x), count: %d, offset: 0x%x\n", data.Regs[0], data.Regs[1], data.Regs[2], data.Regs[3])
		fmt.Println(PrintUnkBytes(data.ArgBuf[0][:], int(data.Regs[2]), "[pwrite64] buf:"))
	case getSyscallId(ProbeVar.READLINKAT):
		fmt.Printf("[readlinkat] dfd: %d, pathname(addr: %x): %s, buf(addr: %x), buflen: %d\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeVar.NEWFSTATAT):
		fmt.Printf("[newfstatat] dfd: %d, pathname(addr: %x): %s, statbuf(addr: %x), flags: 0x%x\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeVar.PTRACE):
		commPath := fmt.Sprintf("/proc/%d/cmdline", data.Regs[1])
		tmp, err := os.ReadFile(commPath)
		var comm string
		if err != nil {
			comm = "fail to read comm"
		} else {
			comm = string(tmp)
		}
		fmt.Printf("[ptrace] request: %d, pid: %d [%s], addr: %x, data: %x\n", data.Regs[0], data.Regs[1], comm, data.Regs[2], data.Regs[3])
	case getSyscallId(ProbeVar.CLONE):
		fmt.Printf("[clone] flags: 0x%x, newsp: %x\n", data.Regs[0], data.Regs[1])
	case getSyscallId(ProbeVar.EXECVE):
		fmt.Printf("[execve] filename(addr: %x): %s\n", data.Regs[0], data.ArgBuf[0])
	case getSyscallId(ProbeVar.GETRANDOM):
		fmt.Printf("[getrandom] buf(addr: %x), buflen: %d, flags: 0x%x\n", data.Regs[0], data.Regs[1], data.Regs[2])
	case getSyscallId(ProbeVar.EXECVEAT):
		fmt.Printf("[execveat] dfd: %d, filename(addr: %x): %s, flags: 0x%x\n", data.Regs[0], data.Regs[1], data.ArgBuf[0], data.Regs[4])
	case getSyscallId(ProbeVar.CLONE3):
		fmt.Printf("[clone3] uargs(addr: %x), size: %d\n", data.Regs[0], data.Regs[1])
	case getSyscallId(ProbeVar.OPENAT2):
		fmt.Printf("[openat2] dfd: %d, filename(addr: %x): %s\n", data.Regs[0], data.Regs[1], data.ArgBuf[0])
	default:
		fmt.Printf("[syscall] id: 0x%x, x0: 0x%x, x1: 0x%x, x2: 0x%x, x3: 0x%x, x4: 0x%x, x5: 0x%x\n", data.SyscallId, data.Regs[0], data.Regs[1], data.Regs[2], data.Regs[3], data.Regs[4], data.Regs[5])
	}
}

type GoUnwindData interface {
	GetRegs() *[31]uint64
	GetPc() uint64
	GetSp() uint64
}

func GetStackUnwindGoWrapper(goData GoUnwindData, pid int) string {
	var tmp C.struct_Data
	regs := goData.GetRegs()
	for i := 0; i < 31; i++ {
		tmp.regs[i] = C.uint64_t(regs[i])
	}
	tmp.pc = C.uint64_t(goData.GetPc())
	tmp.sp = C.uint64_t(goData.GetSp())
	return C.GoString(C.unwind_Online(C.int(pid), (*C.struct_Data)(unsafe.Pointer(&tmp))))
}
