# Application name
APP = process_monitor

# Source files
BPF_SRC = src/$(APP).bpf.c
USER_SRC = src/$(APP).c

# Object files
BPF_OBJ = src/$(APP).bpf.o
USER_OBJ = $(APP).o

# Generated skeleton header
BPF_SKEL = src/$(APP).skel.h

# Compiler and flags
CC = clang
CFLAGS = -g -O2 -Wall
LDFLAGS = -lbpf -lelf

# Default target
all: $(APP)

# Build the user-space application
$(APP): $(USER_OBJ) $(BPF_SKEL)
        $(CC) $(CFLAGS) $(USER_OBJ) -o $(APP) $(LDFLAGS)

# Compile the user-space source
$(USER_OBJ): $(USER_SRC) $(BPF_SKEL)
        $(CC) $(CFLAGS) -c $(USER_SRC) -o $(USER_OBJ)

# Generate the BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ)
        bpftool gen skeleton $< > $@

# Compile the BPF source
$(BPF_OBJ): $(BPF_SRC) src/vmlinux.h
        $(CC) -g -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OBJ) -I./src

# Clean up generated files
clean:
        rm -f $(APP) $(USER_OBJ) $(BPF_OBJ) $(BPF_SKEL)

.PHONY: all clean