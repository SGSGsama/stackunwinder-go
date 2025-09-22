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
}
func start_SysEnterTrace() {
	bpfloader.AttachTp_sysEnter()
	defer bpfloader.CloseTp_sysEnter()
	debug.Debug("tp attached")

	bpfloader.LoadRb(&bpfloader.SysEnterRb, bpfloader.ProbeObjs.SysEnterRb)
	defer bpfloader.CloseRb(&bpfloader.SysEnterRb)
	debug.Debug("tp rb loaded")

	options.SetSysEnterSettings()

	eventReader.Event_reader_sys_enter()

}

func start_UprobeCommonTrace() {
	bpfloader.LoadRb(&bpfloader.UprobeCommonRb, bpfloader.ProbeObjs.UprobeRb)
	defer bpfloader.CloseRb(&bpfloader.UprobeCommonRb)
	debug.Debug("uprobe rb loaded")
	bpfloader.InitUprobe(int(options.TargetPid), options.ParseUprobeSettings())

}
func Main() {
	initLibs()
	options.InitOptions()

	bpfloader.LoadBpfObjs()
	defer bpfloader.CloseBpfObjs()
	debug.Debug("bpf obj loaded")

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
