package options

// 处理用户的的参数，尝试和具体的探针业务代码解耦
import (
	"flag"
	"fmt"
	"os"
	"stackunwinder-go/src/stackunwinder/bpfloader"
	"stackunwinder-go/src/stackunwinder/debug"
	"stackunwinder-go/src/stackunwinder/filters"
	"strings"
)

var (
	TargetPid         uint
	IsDebug           bool
	TargetSyscall     string
	TargetLib         string
	EnableStackUnwind bool
	UprobeSetting     string
)

func InitOptions() {
	flag.Usage = func() {
		helpText := `Usage: stackunwinder [options]

Options:
  -pid, -p        Target process id (required)
  -debug, -d      Enable debug mode
  -syscall, -s    Target syscall name
  -lib, -l        Target library name (default value libc.so) , anonymous memory segment are auto added
  -stack          Enable stack unwinding
  
`
		println(helpText)
	}
	flag.UintVar(&TargetPid, "pid", 0, "Target process id")
	flag.UintVar(&TargetPid, "p", 0, "Target process id")

	flag.BoolVar(&IsDebug, "debug", false, "Enable debug mode")
	flag.BoolVar(&IsDebug, "d", false, "Enable debug mode")

	flag.StringVar(&TargetSyscall, "syscall", "", "Target syscall name")
	flag.StringVar(&TargetSyscall, "s", "", "Target syscall name")

	flag.StringVar(&TargetLib, "lib", "", "Target library name")
	flag.StringVar(&TargetLib, "l", "", "Target library name")

	flag.BoolVar(&EnableStackUnwind, "stack", false, "Enable stack unwinding")

	flag.StringVar(&UprobeSetting, "u", "", "uprobe hook setting")
	flag.StringVar(&UprobeSetting, "uprobe", "", "uprobe hook setting")

	flag.Parse()

	validateRequiredFlags()

	debug.SetDebugMode(IsDebug)
}
func SetSysEnterSettings() {
	filters.SetTargetLib(uint32(TargetPid), strings.Split(TargetLib, ","))
	filters.SetTargetSyscall(strings.Split(TargetSyscall, ","))
	bpfloader.ProbeObjs.TargetPid.Set(uint32(TargetPid))
}
func validateRequiredFlags() {
	if TargetPid == 0 {
		fmt.Println("Error: pid is required")
		flag.Usage()
		os.Exit(0)
	}
}

func ParseUprobeSettings() []bpfloader.InlineHookSetting {
	settings := strings.Split(UprobeSetting, ";")
	debug.Debug("uprobe settings: %v\n", settings)
	os.Exit(0)
	return []bpfloader.InlineHookSetting{}
}
