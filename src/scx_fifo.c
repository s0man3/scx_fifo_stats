#include <bpf/bpf.h>
#include <scx/common.h>
#include <stdio.h>
#include "scx_fifo.bpf.skel.h"

int handle_stats(void *ctx, void *data, size_t size)
{
        printf("%lu\n", *(unsigned long*)data);
        return 0;
}

int main()
{
        struct scx_fifo *skel;
        struct bpf_link *link;
        struct ring_buffer *rb = NULL;
        int err;

        skel = SCX_OPS_OPEN(fifo_ops, scx_fifo);

        SCX_OPS_LOAD(skel, fifo_ops, scx_fifo, uei);
        link = SCX_OPS_ATTACH(skel, fifo_ops, scx_fifo);

        rb = ring_buffer__new(bpf_map__fd(skel->maps.stats),
                              handle_stats, NULL, NULL);

        for (;;) {
                err = ring_buffer__poll(rb, 10000);
                if (err < 0)
                        break;
        }

        ring_buffer__free(rb);
        bpf_link__destroy(link);
        scx_fifo__destroy(skel);
}
