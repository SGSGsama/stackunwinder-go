package stackunwinder

// #include "../linker/wrapper.h"
import "C"

import (
	"os"
	"path"
	"stackunwinder-go/src/stackunwinder/bpfloader"
	"stackunwinder-go/src/stackunwinder/debug"
	eventReader "stackunwinder-go/src/stackunwinder/event_reader"
	"stackunwinder-go/src/stackunwinder/options"
)

func initLibs() {
	exe, _ := os.Executable()
	exeDir := path.Dir(exe)
	C.setupLibEnv(C.CString(exeDir)) // initialize the C library
	if debug.IsDebug {
		C.test_CGO(12345)
	}
	debug.Debug("cgo init done\n")
}
func start_SysEnterTrace() {
	bpfloader.AttachTp_sysEnter()
	defer bpfloader.CloseTp_sysEnter()
	debug.Debug("tp attached\n")

	bpfloader.LoadRb(&bpfloader.SysEnterRb, bpfloader.SysEnterObj.SysEnterRb)
	defer bpfloader.CloseRb(&bpfloader.SysEnterRb)
	debug.Debug("tp rb loaded\n")

	options.SetSysEnterSettings()
	debug.Debug("sys enter settings done\n")
	eventReader.Event_reader_sys_enter()

}

func start_UprobeCommonTrace() {
	bpfloader.InitUprobe(int(options.TargetPid), options.ParseUprobeSettings())
	debug.Debug("uprobe init done\n")
	bpfloader.LoadRb(&bpfloader.UprobeCommonRb, bpfloader.UprobeCommonObj.UprobeRb)
	defer bpfloader.CloseRb(&bpfloader.UprobeCommonRb)
	debug.Debug("uprobe rb loaded\n")

}
func Main() {
	initLibs()
	options.InitOptions()
	bpfloader.DoCommonBpfInit()

	// 直接无脑协程吧，似乎没问题
	if options.TargetSyscall != "" {
		go start_SysEnterTrace()
	}
	if options.UprobeSetting != "" {
		go start_UprobeCommonTrace()
	}
	//这里似乎得阻塞住，不然主线程挂了

	for {
	}
}
