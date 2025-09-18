package stackunwinder

import "log"

func setTargetSyscall(syscalls []string) {
	// debug("%v", SyscallMap)
	for _, syscall := range syscalls {
		index, ok := SyscallMap[syscall]
		if !ok {
			log.Fatalf("Syscall %s not found in syscallMap", syscall)
		}
		debug("Setting target syscall: %s with index: %d\n", syscall, index)
		err := ProbeObjs.probes_Maps.TargetSyscalls.Put(uint32(index), true)
		if err != nil {
			log.Fatalf("Error updating targetSyscalls map for syscall %s: %v", syscall, err)
		}
		debug("Successfully set target syscall: %s\n", syscall)
	}
}
