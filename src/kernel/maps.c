#pragma once
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, PAGE_SIZE * 65536);
} sysEnterRb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, PAGE_SIZE * 65536);
} uprobeRb SEC(".maps"); // 传输uprobeCommon数据

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 0x1c3);
  __type(key, u32);
  __type(value, u8);
} targetSyscalls SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, u64);
} stackBaseAddrTable SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 512);
  __type(key, u32);
  __type(value, u64);
} tidStateMap SEC(
    ".maps"); // 用于防止重复触发sys_enter导致死锁，准确是说是记录对应线程上次一syscall的参数哈希，如果相同就不发送中断