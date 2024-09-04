#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256*1024);
} stats SEC(".maps");

enum event_id {
        SELECT_CPU,
        ENQUEUE,
        RUNNING,
        STOPPING,
};

struct event {
        enum event_id eid;
        s32 pid;
        u64 dsq;
        u32 dsq_nr;
        s32 cpu;
};

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS(fifo_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
        struct event *event;
        struct sched_ext_entity *scx;
        struct scx_dispatch_q *dsq;
        bool is_idle = false;
        s32 cpu;

        cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

        event = bpf_ringbuf_reserve(&stats, sizeof(*event), 0);
        if (!event)
                return 0;

        scx = &p->scx;
        dsq = scx->dsq;

        event->eid = SELECT_CPU;
        event->pid = p->pid;
        event->dsq = dsq->id;
        event->dsq_nr = dsq->nr;
        event->cpu = scx_bpf_task_cpu(p);

        bpf_ringbuf_submit(event, 0);

        return cpu;
}

void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
        struct event *event;
        struct sched_ext_entity *scx;
        struct scx_dispatch_q *dsq;

        event = bpf_ringbuf_reserve(&stats, sizeof(*event), 0);
        if (!event)
                return;

        scx = &p->scx;
        dsq = scx->dsq;

        event->eid = ENQUEUE;
        event->pid = p->pid;
        event->dsq = dsq->id;
        event->dsq_nr = dsq->nr;
        event->cpu = scx_bpf_task_cpu(p);

        bpf_ringbuf_submit(event, 0);

        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
}

void BPF_STRUCT_OPS(fifo_running, struct task_struct *p)
{
        struct event *event;
        struct sched_ext_entity *scx;
        struct scx_dispatch_q *dsq;

        event = bpf_ringbuf_reserve(&stats, sizeof(*event), 0);
        if (!event)
                return;

        scx = &p->scx;
        dsq = scx->dsq;

        event->eid = RUNNING;
        event->pid = p->pid;
        event->dsq = dsq->id;
        event->dsq_nr = dsq->nr;
        event->cpu = scx_bpf_task_cpu(p);

        bpf_ringbuf_submit(event, 0);
}

void BPF_STRUCT_OPS(fifo_stopping, struct task_struct *p, bool runnable)
{
        struct event *event;
        struct sched_ext_entity *scx;
        struct scx_dispatch_q *dsq;

        event = bpf_ringbuf_reserve(&stats, sizeof(*event), 0);
        if (!event)
                return;

        scx = &p->scx;
        dsq = scx->dsq;

        event->eid = STOPPING;
        event->pid = p->pid;
        event->dsq = dsq->id;
        event->dsq_nr = dsq->nr;
        event->cpu = scx_bpf_task_cpu(p);

        bpf_ringbuf_submit(event, 0);
}

s32 BPF_STRUCT_OPS(fifo_init)
{
        return 0;
}

SCX_OPS_DEFINE(fifo_ops,
                .select_cpu     = (void *)fifo_select_cpu,
                .enqueue        = (void *)fifo_enqueue,
                .running        = (void *)fifo_running,
                .stopping       = (void *)fifo_stopping,
                .init           = (void *)fifo_init,
                .name           = "fifo");
