package bpfloader

import "github.com/cilium/ebpf"

// 把整个spec全加载到内核里花的时间有点长了，是时候做选择性加载了

type sysEnterObjsType struct {
	TargetPid      *ebpf.Variable `ebpf:"targetPid"`
	SysEnter       *ebpf.Program  `ebpf:"sys_enter"`
	SysEnterRb     *ebpf.Map      `ebpf:"sysEnterRb"`
	TargetSyscalls *ebpf.Map      `ebpf:"targetSyscalls"`
	TidStateMap    *ebpf.Map      `ebpf:"tidStateMap"`
}

type uprobeCommonObjsType struct {
	CommonUprobe *ebpf.Program `ebpf:"common_uprobe"`
	UprobeRb     *ebpf.Map     `ebpf:"uprobeRb"`
}
