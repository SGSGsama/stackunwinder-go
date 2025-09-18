#pragma once
#include "helper.h"
#include "common.h"
#include "maps.c"
#include "syscall_regs_use.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define CheckNoNULL(ptr)                                                       \
  if (ptr == NULL) {                                                           \
    return true;                                                               \
  }
void bufRead(u8 argBuf[3][512], u64 regs[31], u64 syscall_id) {
  switch (syscall_id) {
  case OPENAT:
  case READ:
  case WRITE:
  case PREAD64:
  case PWRITE64:
  case NEWFSTATAT:
  case EXECVEAT:
  case OPENAT2:
  case READLINKAT:
    bpf_probe_read_user_str(argBuf[0], sizeof(argBuf[0]), (void *)regs[1]);
    break;

  case EXECVE:
    bpf_probe_read_user_str(argBuf[0], sizeof(argBuf[0]), (void *)regs[0]);
    break;
  default:
    break;
  }
}
// int memory_check(u64 idx, struct memoryCheckCtx *ctx) {
//   if (ctx == NULL)
//     return 1;
//   struct memoryCheckCtx *checkCtx = ctx;
//   struct memoryRange *range = bpf_map_lookup_elem(&targetMemoryRange, &idx);
//   if (range == NULL || (range->start == 0)) {
//     return 1; // 如果是空的就说明遍历完了
//   }
//   if (checkCtx->pc >= range->start && checkCtx->pc <= range->end) {
//     checkCtx->found = true;
//     return 1; // stop iterating
//   }
//   return 0; // continue iterating
// }

// bool filter_MemoryRange(uint64_t pc) {

//   bpf_printk("filter_MemoryRange pc: %lx", pc);
//   struct memoryCheckCtx checkCtx = {.found = false, .pc = pc};
//   bpf_loop(MAX_MEMORY_RANGE, memory_check, &checkCtx, 0);
//   return checkCtx.found;
// }

bool filter_syscall(long id) {
  bool *isTarget = bpf_map_lookup_elem(
      &targetSyscalls, &id); // 从表里查看对应的syscall是否要监测
  if (isTarget == NULL) {
    return false;
  }
  bpf_printk("filter_syscall id %d isTarget? : %d ", id, *isTarget);
  return *isTarget;
}
// 获取对应线程的栈基址
// u64 getStackBase(uint32_t tid) {
//   u64 *res = bpf_map_lookup_elem(&stackBaseAddrTable, &tid);
//   if (res == NULL) {
//     u32 mainTid = 0;
//     // 如果没有找到对应的栈基址，尝试获取主线程的栈基址
//     res = bpf_map_lookup_elem(&stackBaseAddrTable, &mainTid);
//     if (res != NULL) {
//       return *res; // 返回主线程的栈基址
//     }
//     return 0;
//   }
//   return *res;
// }

// bool read_full_data(struct pt_regs *regs, long id, struct sysEnterData *data)
// {
//   CheckNoNULL(regs);
//   CheckNoNULL(data);
//   data->pc = regs->pc;
//   data->sp = regs->sp;
//   data->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
//   for (int i = 0; i < 31; i++) {
//     data->regs[i] = regs->regs[i];
//   }
//   u64 stackBase = getStackBase(data->tid);
//   if (stackBase == 0) {
//     bpf_printk("Failed to get stack base for tid: %d\n", data->tid);
//     return 1;
//   }
//   data->stackSize = stackBase - regs->sp;
//   //
//   参考了perf_event_output,直接从sp读栈，栈的大小可以通过当前sp和之前获取的stackEnd计算
//   bpf_probe_read_user(data->stackData,
//                       min(sizeof(data->stackData), data->stackSize),
//                       (void *)regs->sp);
//   bpf_get_current_comm(data->comm, sizeof(data->comm));
//   data->syscall_id = id;
//   bufRead(data->argBuf, data->regs, id);
//   return 0;
// }

__attribute__((always_inline)) bool
read_nostack_data(struct pt_regs *regs, long id,
                  struct sysEnterData_noStack *data) {
  CheckNoNULL(regs);
  CheckNoNULL(data);
  data->pc = regs->pc;
  data->sp = regs->sp;
  data->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  for (int i = 0; i < 31; i++) {
    data->regs[i] = regs->regs[i];
  }
  bpf_get_current_comm(data->comm, sizeof(data->comm));
  data->syscall_id = id;
  bufRead(data->argBuf, data->regs, id);
  return 0;
}
const u64 FNV_64_PRIME = 0x100000001b3ull;
const u64 FNV_64_INIT = 0xcbf29ce484222325ull;
u64 FNV_1a_64(void *data, size_t len) {
  u64 hash = FNV_64_INIT;
  u64 *ptr = (u64 *)data;
  for (size_t i = 0; i < len; i++) {
    hash ^= ptr[i];
    hash *= FNV_64_PRIME;
  }
  return hash;
}
u64 calc_syscall_hash(struct pt_regs *regs) {

  u64 data[8] = {0};
  data[0] = regs->regs[8];
  data[1] = regs->sp;
  for (int i = 0; i < 6; i++) {
    data[i + 2] = regs->regs[i];
  }
  u64 hash = FNV_1a_64(
      &data, min(aarch64_syscall_args_count[min(regs->regs[8], 512)] + 1, 8));

  return hash;
}