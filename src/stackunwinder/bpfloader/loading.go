package bpfloader

import (
	"fmt"
	"log"
	"os"
	"stackunwinder-go/src/stackunwinder/debug"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var ProbeObjs *Probes_Objects = &Probes_Objects{} // save the probes objects globally
var SysEnterTp link.Link = nil                    // 用于跟踪sys_enter的附加点
var SysEnterRb *ringbuf.Reader = nil              // 用于读取sys_enter的ringbuf
var UprobesCommon = []link.Link{}                 // 用于跟踪uprobeCommon的附加点
var UprobeCommonRb *ringbuf.Reader = nil          // 用于读取uprobe追踪数据的ringbuf
func LoadBpfObjs() {
	if err := rlimit.RemoveMemlock(); err != nil { // remove kernel memory lock limit
		log.Fatal(err)
	}
	var opts *ebpf.CollectionOptions
	if debug.IsDebug {
		opts = &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel:     ebpf.LogLevelInstruction,
				LogSizeStart: 1024 * 1024, // 1MB log size
			},
		}
	} else {
		opts = nil
	}
	if err := LoadProbes_Objects(ProbeObjs, opts); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
}
func CloseBpfObjs() {
	if ProbeObjs != nil {
		ProbeObjs.Close()
		ProbeObjs = nil
	}
}

func AttachTp_sysEnter() {
	var err error
	SysEnterTp, err = link.AttachTracing(link.TracingOptions{Program: ProbeObjs.SysEnter, AttachType: ebpf.AttachTraceRawTp}) // attach to sys_enter
	if err != nil {
		log.Fatal(err)
	}
	debug.Debug("tp attached\n")
}
func CloseTp_sysEnter() {
	if SysEnterTp != nil {
		SysEnterTp.Close()
		SysEnterTp = nil
	}
}
func LoadRb(reader **ringbuf.Reader, rb *ebpf.Map) {
	var err error
	*reader, err = ringbuf.NewReader(rb)
	if err != nil {
		log.Fatal(err)
	}
}
func CloseRb(reader **ringbuf.Reader) {
	if *reader != nil {
		(*reader).Close()
		*reader = nil
	}
}

type InlineHookSetting struct {
	SoName        string // 二进制文件名
	SoPath        string // 二进制文件路径，这个提不提供都无所谓，不提供就去maps里解析
	Offset        uint64 // 相对二进制文件起始位置的偏移
	symbol        string // 符号名可选，同时填符号名和偏移优先使用偏移
	str_read_mask uint32 // 读取字符串的掩码
	reg_read_mask uint32 // 读取寄存器的掩码(目前先这样传配置了，不然又得新开map，正好u64塞得下，这个放高32位)
}

// 考虑下面几种配置方案 目前感觉就先支持int和str两种类型的解析就够了
// libsec.so+0x1234 [x0:int,x1:str,....];...
// libsec.so:func_name [x0:int,x1:str,...];...
func InitUprobe(targetPid int, settings []InlineHookSetting) { // 打算寻址采用soName+偏移的格式 libsec.so+0x123 ...
	for _, setting := range settings {
		uprobeOps := link.UprobeOptions{}
		process, err := link.OpenExecutable(setting.SoPath)
		if err != nil {
			log.Fatal(err)
		}
		uprobeOps.Address = setting.Offset
		uprobeOps.PID = targetPid
		uprobeOps.Cookie = uint64(setting.reg_read_mask)<<32 | uint64(setting.str_read_mask) // 高32位是寄存器掩码 低32位是字符串掩码
		res, err := process.Uprobe(setting.symbol, ProbeObjs.CommonUprobe, &uprobeOps)
		if debug.IsDebug && setting.symbol == "" {
			setting.symbol = "offset_0x" + strconv.FormatUint(setting.Offset, 16)
		}
		if err != nil {
			if setting.symbol == "" {
				setting.symbol = "offset_0x" + strconv.FormatUint(setting.Offset, 16)
			}
			fmt.Printf("err uprobe [%s]", setting.symbol)
			os.Exit(0)
		}
		debug.Debug("uprobe [%s]attached\n", setting.symbol)

		UprobesCommon = append(UprobesCommon, res)
	}
}
func CloseUprobesCommon() {
	for _, link := range UprobesCommon {
		if link != nil {
			link.Close()
		}
	}
	UprobesCommon = []link.Link{}
}
