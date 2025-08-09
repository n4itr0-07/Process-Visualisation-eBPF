// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "process_monitor.h"

// Optional: Define a license for the program. This is required for some helpers.
char LICENSE[] SEC("license") = "GPL";

// Define the ring buffer map for sending data to user space.
// This is the modern replacement for perf buffers.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} rb SEC(".maps");

// Attach to the standard sched_process_exit tracepoint.
// The context argument type 'struct trace_event_raw_sched_process_exit' is
// what the kernel provides for this tracepoint. libbpf uses BTF to ensure
// the fields are correctly accessed.
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, ppid;
    int exit_code;

    // Get the PID of the exiting process.
    pid = bpf_get_current_pid_tgid() >> 32;

    // Reserve space on the ring buffer for our event.
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        // Failed to reserve space, perhaps the buffer is full.
        // Nothing we can do, so we return.
        return 0;
    }

    // Get a pointer to the current task's task_struct.
    // This is the main entry point for accessing process information.
    task = (struct task_struct *)bpf_get_current_task();

    // Populate the event structure using BPF CO-RE helpers.
    // This ensures portability across different kernel versions.

    // Read the parent's PID.
    // BPF_CORE_READ can traverse pointers. Here it reads task->real_parent->tgid.
    BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);

    // Read the exit code.
    BPF_CORE_READ_INTO(&exit_code, task, exit_code);

    e->pid = pid;
    e->ppid = ppid;
    // The exit code is encoded. The lower 8 bits are the signal number (if killed)
    // or 0. The next 8 bits are the exit status.
    e->exit_code = (exit_code >> 8) & 0xff;

    // Read the command name.
    bpf_core_read_str(&e->comm, sizeof(e->comm), &task->comm);

    // Submit the event to the ring buffer for user-space to consume.
    bpf_ringbuf_submit(e, 0);

    return 0;
}