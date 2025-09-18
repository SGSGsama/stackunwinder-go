//+build ignore
#include "common.h"
#include "helper.c"
#include "maps.c"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SIGSTOP 19

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id) {
  // bpf_printk("pid : %d   target : %d \n", (bpf_get_current_pid_tgid() >> 32),
  //            targetPid);
  if ((bpf_get_current_pid_tgid() >> 32) != targetPid) {
    return 0;
  }
  if (!filter_syscall(id))
    return 0;
  // bpf_printk("pid: %d nr: %d \n", bpf_get_current_pid_tgid() >> 32, id);
  int tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  // enum tid_State *state = bpf_map_lookup_elem(&tidStateMap, &tid);
  // bpf_printk("tid:  %d nr %d state: %d\n", tid, id,
  //            state == NULL ? -1 : *state);
  // if (state != NULL && *state == STATE_RESUME) {
  //   bpf_map_delete_elem(&tidStateMap, &tid);
  //   return 0;
  // }
  // enum tid_State new_state = STATE_CAPTURE;
  // bpf_map_update_elem(&tidStateMap, &tid, &new_state, BPF_ANY);
  u64 *lastHash = bpf_map_lookup_elem(&tidStateMap, &tid);
  u64 hash = calc_syscall_hash(regs);
  bpf_printk("syscall hash: %llu ", hash);
  if (lastHash != NULL && *lastHash == hash)
    return 0;
  bpf_map_update_elem(&tidStateMap, &tid, &hash, BPF_ANY);
  bpf_send_signal(SIGSTOP);

  // prepare the stack data
  struct sysEnterData_noStack *data =
      bpf_ringbuf_reserve(&sysEnterRb, sizeof(struct sysEnterData_noStack), 0);
  if (data == NULL) {
    bpf_printk("Failed to reserve space in ring buffer\n");
    return 0;
  }
  // 这里把相关的数据读取一下
  int err = read_nostack_data(regs, id, data);
  if (err) {
    bpf_ringbuf_discard(data, 0);
    return 0;
  }
  bpf_ringbuf_submit(data, 0);

  // bpf_send_signal(SIGSTOP);
  return 0;
}