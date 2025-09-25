#include "common.h"
#include "maps.c"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
__attribute__((used)) static struct uprobeCommonData dummy_uprobe_data;
SEC("uprobe/common_uprobe")
int common_uprobe(struct pt_regs *ctx) {
  struct uprobeCommonData *data =
      bpf_ringbuf_reserve(&uprobeRb, sizeof(struct uprobeCommonData), 0);
  if (!data) {
    bpf_printk("fail to reserve ringbuf space (uprobe common)\n");
    return 0;
  }
  u64 regCollectSettingMask = bpf_get_attach_cookie(
      ctx); // 直接拿bpf_cookie传配置掩码，这样正好解决了字符串不好作为hashmap映射的问题
  data->mask = regCollectSettingMask;
  bpf_printk("uprobe hit at 0x%llx\n", ctx->pc);
  data->pc = ctx->pc;
  data->sp = ctx->sp;
  data->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  bpf_printk("uprobe pc:%llx sp:%llx tid:%d\n", data->pc, data->sp, data->tid);
  if (bpf_probe_read_kernel(data->regs, sizeof(data->regs), ctx->regs)) {
    bpf_printk("read reg fail\n");
    bpf_ringbuf_discard(data, 0);
    return 0;
  }
  bpf_printk("read reg success\n");
  u8 strCollectCnt = 0;
  if (data->mask != 0) {
    // bpf_loop(31, reg_str_read_helper, data, 0);
    for (int i = 0; i < 31 && strCollectCnt < 8;
         i++) { // 这里只采前8个设置为采集的，多余的直接抛弃
      if (data->mask & (1 << i)) {

        bpf_probe_read_user(data->buf[strCollectCnt],
                            sizeof(data->buf[strCollectCnt]),
                            (void *)(data->regs[i]));
        bpf_printk("collect str for x%d ('0x%02x,0x%02x,0x%02x')\n", i,
                   data->buf[strCollectCnt][0], data->buf[strCollectCnt][1],
                   data->buf[strCollectCnt][2]);
        strCollectCnt++;
      }
    }
  }
  bpf_send_signal(SIGSTOP);
  bpf_ringbuf_submit(data, 0);
  return 0;
}