package stackunwinder

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type MemoryRange struct {
	Start uint64
	End   uint64
}

var MemoryRanges []MemoryRange

func setTargetLib(pid uint32, libs []string) {
	MemoryRanges = []MemoryRange{}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		log.Fatalln("Error reading maps file:", err)
	}
	lines := strings.Split(string(maps), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		debug("parts: %v\n", parts)
		if len(parts) == 0 {
			continue
		}
		if !strings.Contains(parts[1], "x") {
			continue
			//没执行权限也跳过，应该没问题
		}
		if len(parts) < 6 {
			// 对于匿名内存直接添加监视，有可能被用作动态执行字节码
			memoryRangeStr := strings.Split(parts[0], "-")
			debug("%s\n", line)
			var memoryRange MemoryRange
			memoryRange.Start, err = strconv.ParseUint(memoryRangeStr[0], 16, 64)
			if err != nil {
				log.Fatalln("Error parsing memory range start:", err)
			}
			memoryRange.End, err = strconv.ParseUint(memoryRangeStr[1], 16, 64)
			if err != nil {
				log.Fatalln("Error parsing memory range end:", err)
			}
			fmt.Printf("monitoring anonymous memory range: %x-%x\n", memoryRange.Start, memoryRange.End)
			MemoryRanges = append(MemoryRanges, memoryRange)
			continue
		}
		memoryName := parts[5]
		for _, lib := range libs { // 这里筛一下有名字的内存段
			if strings.Contains(memoryName, lib) {
				memoryRangeStr := strings.Split(parts[0], "-")
				debug("%s\n", line)
				var memoryRange MemoryRange
				memoryRange.Start, err = strconv.ParseUint(memoryRangeStr[0], 16, 64)
				if err != nil {
					log.Fatalln("Error parsing memory range start:", err)
				}
				memoryRange.End, err = strconv.ParseUint(memoryRangeStr[1], 16, 64)
				if err != nil {
					log.Fatalln("Error parsing memory range end:", err)
				}
				fmt.Printf("monitoring lib: %s  range: %x-%x\n", memoryName, memoryRange.Start, memoryRange.End)
				MemoryRanges = append(MemoryRanges, memoryRange)
			}
		}
	}
}

func checkMemoryRange(pc uint64) bool {
	for _, memoryRange := range MemoryRanges {
		if pc >= memoryRange.Start && pc < memoryRange.End {
			return true
		}
	}
	return false
}
