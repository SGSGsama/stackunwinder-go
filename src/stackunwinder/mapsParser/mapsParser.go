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

