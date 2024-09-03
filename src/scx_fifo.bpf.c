#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256*1024);
} stats SEC(".maps");

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS(fifo_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
        u64 *event;
        bool is_idle = false;
        s32 cpu;

        cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

        event = bpf_ringbuf_reserve(&stats, sizeof(u64), 0);
        if (!event)
                return 0;
        *event = ((u64)p->pid << 32) + (u32)cpu;
        bpf_ringbuf_submit(event, 0);

        return cpu;
}

void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
        u64 *event;

        event = bpf_ringbuf_reserve(&stats, sizeof(u64), 0);
        if (!event)
                return;
        *event = (u64)p->pid;
        bpf_ringbuf_submit(event, 0);

        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
}

s32 BPF_STRUCT_OPS(fifo_init)
{
        return 0;
}

SCX_OPS_DEFINE(fifo_ops,
                .select_cpu     = (void *)fifo_select_cpu,
                .enqueue        = (void *)fifo_enqueue,
                .init           = (void *)fifo_init,
                .name           = "fifo");
