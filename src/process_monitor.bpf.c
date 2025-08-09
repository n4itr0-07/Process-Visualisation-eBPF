// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "process_monitor.h"


char LICENSE[] SEC("license") = "GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); 
} rb SEC(".maps");


SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, ppid;
    int exit_code;

   
    pid = bpf_get_current_pid_tgid() >> 32;

    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        
        return 0;
    }

    
    task = (struct task_struct *)bpf_get_current_task();

    
    BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);

    
    BPF_CORE_READ_INTO(&exit_code, task, exit_code);

    e->pid = pid;
    e->ppid = ppid;
    
    e->exit_code = (exit_code >> 8) & 0xff;

    
    bpf_core_read_str(&e->comm, sizeof(e->comm), &task->comm);

    
    bpf_ringbuf_submit(e, 0);

    return 0;
}