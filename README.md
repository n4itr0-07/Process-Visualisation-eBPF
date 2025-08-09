# Process Exit Monitor with eBPF

A simple yet powerful process and thread exit monitor built with eBPF and `libbpf`. This tool attaches to the `sched_process_exit` tracepoint to capture process exit events directly from the Linux kernel. It efficiently gathers and displays key information like PID, Parent PID (PPID), the command name, and the final exit code.

This project demonstrates the use of modern eBPF with CO-RE (Compile Once - Run Everywhere) for high portability and performance.

-----

## Demo

Here is a quick demo of the monitor in action. The top panel runs the monitor, while the bottom panel runs various commands.

```bash
┌──(root)㉿(ubuntu)-[~/Process-Visualisation-eBPF]
└─⧽ sudo ./process_monitor
Successfully started! Tracing process exits... Press Ctrl-C to exit.
Process exited: PID=5120, PPID=4890, COMM=ls, EXIT_CODE=0
Process exited: PID=5121, PPID=4890, COMM=whoami, EXIT_CODE=0
Process exited: PID=5122, PPID=4890, COMM=sleep, EXIT_CODE=0
Process exited: PID=5124, PPID=4890, COMM=cat, EXIT_CODE=1
^C
```

-----

## Features

- **Real-time Monitoring**: Captures process and thread exit events as they happen.
- **CO-RE Ready**: Uses modern eBPF with CO-RE for maximum portability across different kernel versions.
- **Lightweight & Efficient**: All event gathering is done inside the kernel, ensuring minimal performance overhead.
- **Detailed Information**: Provides PID, PPID, command name, and the exit code for each event.

-----

## 1\. Prerequisites

This project is designed for a **Linux environment**. If you are on Windows, you must use the **Windows Subsystem for Linux (WSL 2)** to run this code.

You will need the following tools and libraries installed:

- `clang`
- `make`
- `libelf-dev` (or `elfutils-libelf-devel` on Fedora/CentOS)
- `libbpf-dev` (or `libbpf-devel` on Fedora/CentOS)
- `bpftool` (usually included in `linux-tools-common` or similar packages)

#### Quick Install Command (Debian/Ubuntu)

You can install all dependencies with the following command:

```bash
sudo apt-get update
sudo apt-get install -y clang make libelf-dev libbpf-dev linux-tools-common linux-tools-generic
```

-----

## 2\. Setup and Compilation

Follow these steps to get the program running.

#### Step 1: Clone the Repository

```bash
git clone https://github.com/n4itr0-07/Process-Visualisation-eBPF.git
cd Process-Visualisation-eBPF
```

#### Step 2: Generate `vmlinux.h`

For CO-RE to work, the eBPF program needs access to all kernel type definitions. We can generate a special header file, `vmlinux.h`, using `bpftool`.

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
```

> **Note**: This step is crucial. It creates the `vmlinux.h` file inside the `src` directory, which is necessary for the next step.

#### Step 3: Compile the Project

With all dependencies in place, use the `Makefile` to build the application.

```bash
make
```

This command will:

1. Compile the eBPF kernel code (`src/process_monitor.bpf.c`).
2. Generate a BPF skeleton header (`src/process_monitor.skel.h`).
3. Compile the user-space application (`src/process_monitor.c`).
4. Link everything into a final executable named `process_monitor`.

-----

## 3\. Usage

### Step 1: Run the Monitor

The program must be run with `sudo` to have the required permissions to load eBPF programs into the kernel.

```bash
sudo ./process_monitor
```

You should see the message: `Successfully started! Tracing process exits... Press Ctrl-C to exit.`

#### Step 2: Generate Events

To test the monitor, **open a second terminal** and run any commands. For example:

```bash
ls -l
whoami
sleep 1
cat /nonexistent/file
```

#### Step 3: Observe the Output

Switch back to your first terminal. You will see the exit events for the commands you just ran, including their exit codes.

#### Step 4: Stop the Monitor

Press `Ctrl+C` in the terminal where the monitor is running to stop it and clean up the attached eBPF program.

-----

## Project Structure

```
.
├── Makefile                # Automates the build process
└── src/
    ├── process_monitor.bpf.c # eBPF C code (runs in kernel)
    ├── process_monitor.c     # User-space C code (loads and reads from BPF program)
    ├── process_monitor.h     # Shared header for data structures
    └── vmlinux.h             # (Generated) Kernel type definitions for CO-RE
```
