#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "process_monitor.h"
#include "process_monitor.skel.h" 

static volatile bool exiting = false;


static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Process exited: PID=%d, PPID=%d, COMM=%s, EXIT_CODE=%d\n",
           e->pid, e->ppid, e->comm, e->exit_code);
    return 0;
}

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct process_monitor_bpf *skel;
    int err;

    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    
    skel = process_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = process_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    
    err = process_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Tracing process exits... Press Ctrl-C to exit.\n");

   
    while (!exiting) {

        err = ring_buffer__poll(rb, 100 /* timeout, ms */);

        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
   
    ring_buffer__free(rb);
    process_monitor_bpf__destroy(skel);
    return -err;
}