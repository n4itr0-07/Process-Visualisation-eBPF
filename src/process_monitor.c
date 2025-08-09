#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "process_monitor.h"
#include "process_monitor.skel.h" // The generated BPF skeleton header

static volatile bool exiting = false;

// Callback function for handling events from the ring buffer.
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Process exited: PID=%d, PPID=%d, COMM=%s, EXIT_CODE=%d\n",
           e->pid, e->ppid, e->comm, e->exit_code);
    return 0;
}

// Signal handler to gracefully exit the program.
static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct process_monitor_bpf *skel;
    int err;

    // Set up signal handler for clean exit.
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open, load, and verify the BPF application (skeleton).
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

    // Attach the tracepoint handler.
    err = process_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Set up the ring buffer manager.
    // The ring buffer map is named 'rb' in the BPF code.
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Tracing process exits... Press Ctrl-C to exit.\n");

    // Main event loop.
    while (!exiting) {
        // Poll the ring buffer for new events with a 100ms timeout.
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        // Ctrl-C will cause -EINTR
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
    // Free resources.
    ring_buffer__free(rb);
    process_monitor_bpf__destroy(skel);
    return -err;
}