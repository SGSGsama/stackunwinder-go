package bpfloader

import (
	"log"
	"stackunwinder-go/src/stackunwinder/debug"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var ProbeObjs *Probes_Objects = &Probes_Objects{} // save the probes objects globally
var SysEnterTp link.Link = nil                    // 用于跟踪sys_enter的附加点
var SysEnterRb *ringbuf.Reader = nil              // 用于读取sys_enter的ringbuf
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

func LoadRb_forSysEnter() {
	var err error
	SysEnterRb, err = ringbuf.NewReader(ProbeObjs.SysEnterRb)
	if err != nil {
		log.Fatal(err)
	}
}
func CloseRb_forSysEnter() {
	if SysEnterRb != nil {
		SysEnterRb.Close()
		SysEnterRb = nil
	}
}
