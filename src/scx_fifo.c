#include <bpf/bpf.h>
#include <scx/common.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "scx_fifo.bpf.skel.h"

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

pid_t pid;

int handle_stats(void *ctx, void *data, size_t size)
{
        struct event *event = data;
        if (event->pid == pid)
                return 0;
        printf("%3d\t%3d\t%3lu\t%3u\t%3d\n",
                event->eid, event->pid, event->dsq, event->dsq_nr, event->cpu);
        return 0;
}

int main()
{
        struct scx_fifo *skel;
        struct bpf_link *link;
        struct ring_buffer *rb = NULL;
        int err;

        pid = getpid();

        skel = SCX_OPS_OPEN(fifo_ops, scx_fifo);

        SCX_OPS_LOAD(skel, fifo_ops, scx_fifo, uei);
        link = SCX_OPS_ATTACH(skel, fifo_ops, scx_fifo);

        rb = ring_buffer__new(bpf_map__fd(skel->maps.stats),
                              handle_stats, NULL, NULL);

        printf("EID     PID     DSQ     DSQ_NR  CPU\n");

        for (;;) {
                err = ring_buffer__poll(rb, 1000);
                if (err < 0)
                        break;
        }

        ring_buffer__free(rb);
        bpf_link__destroy(link);
        scx_fifo__destroy(skel);
}
