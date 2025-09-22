#include "common.h"
#include "helper.c"
#include "maps.c"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
SEC("uprobe/common_uprobe")
int common_uprobe(struct pt_regs *ctx) {
  struct uprobeCommonData *data =
      bpf_ringbuf_reserve(&uprobeRb, sizeof(struct uprobeCommonData), 0);
  if (!data) {
    bpf_printk("fail to reserve ringbuf space (uprobe common)\n");
    return 0;
  }
  if (!read_uprobe_data(ctx, data)) {
    bpf_ringbuf_discard(data, 0);
    return 0;
  }
  bpf_send_signal(SIGSTOP);
  bpf_ringbuf_submit(data, 0);
  return 0;
}