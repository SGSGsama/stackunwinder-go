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
  -u -uprobe	  Uprobe inline hook setting (support reg:x0~x30,readType:int,str(means byte dump) )   
			      format:
				  	example 0x1: libsec.so+0x1234 [x0:int,x1:str,.... (split with ',') ];...(more inlinehook addr split with ';')
					example 0x2: libsec.so:func_name [x0:int,x1:str,...]; the same as above
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
	debug.Debug("TargetPid: %d\n", TargetPid)
	debug.Debug("TargetSyscall: %s\n", TargetSyscall)
	debug.Debug("TargetLib: %s\n", TargetLib)
	debug.Debug("EnableStackUnwind: %v\n", EnableStackUnwind)
	debug.Debug("UprobeSetting: %s\n", UprobeSetting)
}
func SetSysEnterSettings() {
	filters.SetTargetLib(uint32(TargetPid), strings.Split(TargetLib, ","))
	filters.SetTargetSyscall(strings.Split(TargetSyscall, ","))
	bpfloader.BpfVar.TargetPid.Set(uint32(TargetPid))
}
func validateRequiredFlags() {
	if TargetPid == 0 {
		fmt.Println("Error: pid is required")
		flag.Usage()
		os.Exit(0)
	}
}

func ParseUprobeSettings() []bpfloader.InlineHookSetting {
	res := []bpfloader.InlineHookSetting{}
	settings := strings.Split(UprobeSetting, ";")
	if debug.IsDebug {
		for _, s := range settings {
			fmt.Printf("%s\n", s)
		}
	}
	for _, setting := range settings {
		tmp := bpfloader.InlineHookSetting{}
		infos := strings.Split(setting, "[") // 这里其实比较tricky，不过好像没什么别的好办法
		if len(infos) < 2 {
			fmt.Printf("Error: invalid uprobe setting %s\n", setting)
			os.Exit(0)
		}
		addrInfo := strings.TrimSpace(infos[0])
		debug.Debug("addrInfo: %s\n", addrInfo)
		regInfo := strings.TrimRight(strings.TrimSpace(infos[1]), "]")
		debug.Debug("regInfo: %s\n", regInfo)
		// 解析一下符号和地址
		if strings.Contains(addrInfo, "+") { // libsec.so+0x1234
			parts := strings.Split(addrInfo, "+")
			if len(parts) != 2 {
				fmt.Printf("Error: invalid uprobe address info %s\n", addrInfo)
				os.Exit(0)
			}
			tmp.SoName = strings.TrimSpace(parts[0])
			offsetStr := strings.TrimSpace(parts[1])
			var offset uint64
			_, err := fmt.Sscanf(offsetStr, "0x%x", &offset)
			if err != nil {
				fmt.Printf("Error: invalid uprobe offset %s\n", offsetStr)
				os.Exit(0)
			}
			tmp.Offset = offset
			debug.Debug("SoPath: %s, Offset: 0x%x\n", tmp.SoName, tmp.Offset)
		} else if strings.Contains(addrInfo, ":") { // libsec.so:func_name
			parts := strings.Split(addrInfo, ":")
			if len(parts) != 2 {
				fmt.Printf("Error: invalid uprobe address info %s\n", addrInfo)
				os.Exit(0)
			}
			tmp.SoName = strings.TrimSpace(parts[0])
			tmp.Symbol = strings.TrimSpace(parts[1])
			debug.Debug("SoPath: %s, FuncName: %s\n", tmp.SoName, tmp.Symbol)
		} else {
			fmt.Printf("Error: invalid uprobe address info %s\n", addrInfo)
			os.Exit(0)
		}
		//这里解析寄存器读取 x0~x30
		reads := strings.Split(regInfo, ",")
		for _, r := range reads {
			parts := strings.Split(r, ":")
			if len(parts) != 2 {
				fmt.Printf("Error: invalid uprobe reg read info %s\n", r)
			}
			regRead := strings.TrimSpace(parts[0])
			regType := strings.TrimSpace(parts[1])
			if regRead[0] != 'x' {
				fmt.Printf("Error: invalid reg,only x0~x30 supported %s\n", regRead)
				os.Exit(0)
			}
			var regIndex int
			_, err := fmt.Sscanf(regRead, "x%d", &regIndex)
			if err != nil || regIndex < 0 || regIndex > 30 {
				fmt.Printf("Error: invalid reg,only x0~x30 supported %s\n", regRead)
				if err != nil {
					fmt.Println(err)
				}
				os.Exit(0)
			}
			tmp.Reg_read_mask |= 1 << regIndex
			switch regType {
			case "int":
			case "str":
				tmp.Str_read_mask |= 1 << regIndex
			default:
				fmt.Printf("Error: invalid reg type,only int and str supported %s\n", regType)
				os.Exit(0)
			}
			debug.Debug("reg:%s regIdx:%d type:%s \n", regRead, regIndex, regType)
			debug.Debug("reading mask: %31b\n", tmp.Reg_read_mask)
			debug.Debug("str     mask: %31b\n", tmp.Str_read_mask)
		}
		res = append(res, tmp)
	}
	return res
}
