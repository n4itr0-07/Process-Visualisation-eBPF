#ifndef __PROCESS_MONITOR_H
#define __PROCESS_MONITOR_H

#define TASK_COMM_LEN 16

struct event {
    int pid;
    int ppid;
    int exit_code;
    char comm[TASK_COMM_LEN];
};

#endif /* __PROCESS_MONITOR_H */