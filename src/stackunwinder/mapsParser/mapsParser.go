package mapsparser

import (
	"fmt"
	"os"
	"stackunwinder-go/src/stackunwinder/debug"
	"strconv"
	"strings"
)

var soPathCache = make(map[string]string)
var SoBaseAddr = make(map[string]uint64)
var SoSegmentBase = make(map[string]uint64)
var EXE_BASE uint64 = 0

func ConvertSimpleOffsetToUprobeOffset(soName string, offset uint64) uint64 {
	debug.Debug("%s EXE_BASE: %x,offset:  %x SoBaseAddr: %x, SoSegmentBase: %x\n", soName, EXE_BASE, offset, SoBaseAddr[soName], SoSegmentBase[soName])
	return EXE_BASE + offset - SoBaseAddr[soName] + SoSegmentBase[soName]
}

func GetSoPath(soName string, pid int) string {
	res, ok := soPathCache[soName] // 缓存
	if ok {
		debug.Debug("soPathCache hit: %s -> %s\n", soName, res)
		return res
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)) // 直接读maps获取内存布局
	if err != nil {
		fmt.Println("Error reading maps file:", err)
		return ""
	}
	lines := strings.Split(string(maps), "\n")
	for _, line := range lines {
		if EXE_BASE == 0 {
			EXE_BASE, err = strconv.ParseUint(strings.Split(strings.Split(line, " ")[0], "-")[0], 16, 64)
			if err != nil {
				fmt.Printf("Error parsing EXE_BASE: %v\n", err)
			}
		}
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		if strings.Contains(parts[1], "x") == false { // 没有执行权限的跳过
			continue
		}
		memoryName := parts[5]
		if strings.Contains(memoryName, soName) {
			soPathCache[soName] = memoryName // 缓存
			SoBaseAddr[soName], err = strconv.ParseUint(strings.Split(parts[0], "-")[0], 16, 64)
			if err != nil {
				fmt.Printf("Error parsing base address for %s: %v\n", soName, err)
				os.Exit(0)
			}
			SoSegmentBase[soName], err = strconv.ParseUint(parts[2], 16, 64) // 取偏移量作为段基址
			if err != nil {
				fmt.Printf("Error parsing base address for %s: %v\n", soName, err)
				os.Exit(0)
			}
		}
	}
	res, ok = soPathCache[soName]
	if !ok {
		fmt.Printf("Error: soFile %s not found in pid %d maps\n", soName, pid)
		os.Exit(0)
	}
	return res
}

// func setStackAddrTable(pid int) {
// 	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)) // 直接读maps获取内存布局
// 	if err != nil {
// 		log.Fatalln("Error reading maps file:", err)
// 	}
// 	lines := strings.Split(string(maps), "\n")
// 	for _, line := range lines {
// 		parts := strings.Fields(line)
// 		Debug("parts: %v\n", parts)
// 		if len(parts) < 6 {
// 			continue
// 		}
// 		memoryName := parts[5]                       // 提取段名
// 		if strings.Contains(memoryName, "[stack]") { //处理主线程
// 			memoryRangeStr := strings.Split(parts[0], "-")
// 			Debug("%v\n", memoryRangeStr)
// 			stackEnd, err := strconv.ParseUint(memoryRangeStr[1], 16, 64)
// 			if err != nil {
// 				log.Fatalln("Error parsing stack end:", err)
// 			}
// 			Debug("set main thread stackend to %x\n", stackEnd)
// 			var __tidmain uint32 = 0
// 			ProbeObjs.probes_Maps.StackBaseAddrTable.Put(&__tidmain, &stackEnd) // 主线程的栈地址放在0位，主要没法提前知道主线程tid
// 			if IsDebug {
// 				var __tmp uint64
// 				ProbeObjs.probes_Maps.StackBaseAddrTable.Lookup(&__tidmain, &__tmp)
// 				Debug("set stackend %x \n", __tmp)
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
// 			Debug("%v\n", memoryRangeStr)
// 			stackEnd, err := strconv.ParseUint(memoryRangeStr[1], 16, 64)
// 			if err != nil {
// 				log.Fatalln("Error parsing stack end:", err)
// 			}
// 			Debug("set thread %d stackend to %x\n", tid, stackEnd)
// 			ProbeObjs.probes_Maps.StackBaseAddrTable.Put(&tid, &stackEnd)
// 			if IsDebug {
// 				var __tmp uint64
// 				ProbeObjs.probes_Maps.StackBaseAddrTable.Lookup(&tid, &__tmp)
// 				Debug("set stackend %x \n", __tmp)
// 			}
// 		}
// 	}
// }
