package bpfloader

// 这里给泛型搞一搞getter，想了半天只能这么搞了
func (data *Probes_UprobeCommonData) GetRegs() *[31]uint64 { return &data.Regs }
func (data *Probes_UprobeCommonData) GetPc() uint64        { return data.Pc }
func (data *Probes_UprobeCommonData) GetSp() uint64        { return data.Sp }

func (data *Probes_SysEnterDataNoStack) GetRegs() *[31]uint64 { return &data.Regs }
func (data *Probes_SysEnterDataNoStack) GetPc() uint64        { return data.Pc }
func (data *Probes_SysEnterDataNoStack) GetSp() uint64        { return data.Sp }
