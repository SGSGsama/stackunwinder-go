#pragma once
#include "common.h"
#include <bpf/bpf_helpers.h>

void bufRead(u8 argBuf[3][512], u64 regs[31], u64 syscall_id);

bool filter_MemoryRange(uint64_t pc);

bool filter_syscall(long id);

u64 min(u64 a, u64 b) { return a < b ? a : b; }

// u64 getStackBase(uint32_t tid);

bool read_full_data(struct pt_regs *regs, long id, struct sysEnterData *data);
__attribute__((always_inline)) bool
read_nostack_data(struct pt_regs *regs, long id,
                  struct sysEnterData_noStack *data);