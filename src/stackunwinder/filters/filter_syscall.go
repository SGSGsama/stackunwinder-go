package filters

import (
	"log"
	"stackunwinder-go/src/stackunwinder/bpfloader"
	"stackunwinder-go/src/stackunwinder/debug"
	"stackunwinder-go/src/stackunwinder/utilis"
)

func SetTargetSyscall(syscalls []string) {
	// Debug("%v", SyscallMap)
	for _, syscall := range syscalls {
		index, ok := utilis.SyscallMap[syscall]
		if !ok {
			log.Fatalf("Syscall %s not found in syscallMap", syscall)
		}
		debug.Debug("Setting target syscall: %s with index: %d\n", syscall, index)
		err := bpfloader.ProbeObjs.Probes_Maps.TargetSyscalls.Put(uint32(index), true)
		if err != nil {
			log.Fatalf("Error updating targetSyscalls map for syscall %s: %v", syscall, err)
		}
		debug.Debug("Successfully set target syscall: %s\n", syscall)
	}
}
