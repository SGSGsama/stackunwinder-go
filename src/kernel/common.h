#pragma once
#include "vmlinux.h"
volatile uint32_t targetPid = 0;
#define PAGE_SIZE 4096
#define SIGSTOP 19
struct sysEnterData {
  u64 regs[31], pc, sp;
  char stackData[65536];
  uint64_t stackSize;
  u8 comm[32];
  u8 argBuf[3][512];
  u64 syscall_id;
  u32 tid;
};
struct sysEnterData_noStack {
  u64 regs[31], pc, sp;
  u8 comm[32];
  u8 argBuf[3][512];
  u64 syscall_id;
  u32 tid;
  long sig_state;
};
// struct memoryRange {
//   uint64_t start;
//   uint64_t end;
// };
struct uprobeCommonData {
  u64 regs[31];
  u64 pc, sp;
  u32 tid;
  u8 buf[8][1024]; // 每个编号最多读1kb，再多感觉不合适了,读8个寄存器应该够用了
                   // 具体说就是buf[readstr[1]]代表1号寄存器读到的字符串
  u64 mask; // 回传掩码用于数据解析
};
const uint32_t OPENAT = 56;
const uint32_t READ = 63;
const uint32_t WRITE = 64;
const uint32_t PREAD64 = 0x43;
const uint32_t PWRITE64 = 0x44;
const uint32_t READLINKAT = 0x4e;
const uint32_t NEWFSTATAT = 0x4f;
const uint32_t PTRACE = 0x75;
const uint32_t CLONE = 0xdc;
const uint32_t EXECVE = 0xdd;
const uint32_t GETRANDOM = 0x116;
const uint32_t EXECVEAT = 0x119;
const uint32_t CLONE3 = 0x1b3;
const uint32_t OPENAT2 = 0x1b5;
