# Makefile for building individual .c files in srcs folder

# Compiler and compiler flags
CC := gcc
CFLAGS := -Wall -Wextra -std=gnu11
LDFLAGS :=

# Directories
SRC_DIR := srcs
BIN_DIR := binaries

# Default target to build all executables
all:
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SRC_DIR)/basic_test.c -o $(BIN_DIR)/basic_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/breakpoint_test.c -o $(BIN_DIR)/breakpoint_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/memory_test.c -o $(BIN_DIR)/memory_test $(LDFLAGS)
	$(CC) $(CFLAGS) -fPIE -pie $(SRC_DIR)/basic_test_pie.c -o $(BIN_DIR)/basic_test_pie $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/benchmark.c -o $(BIN_DIR)/benchmark $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/backtrace.c -o $(BIN_DIR)/backtrace $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/brute_test.c -o $(BIN_DIR)/brute_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/speed_test.c -o $(BIN_DIR)/speed_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/thread_test.c -o $(BIN_DIR)/thread_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/complex_thread_test.c -o $(BIN_DIR)/complex_thread_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/watchpoint_test.c -o $(BIN_DIR)/watchpoint_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/signal_handling_test.c -o $(BIN_DIR)/signal_handling_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/signals_multithread_undet_test.c -o $(BIN_DIR)/signals_multithread_undet_test $(LDFLAGS)
	$(CC) $(CFLAGS) $(SRC_DIR)/segfault_test.c -o $(BIN_DIR)/segfault_test $(LDFLAGS)
	

# Clean rule to remove compiled files
clean:
	rm -rf $(BIN_DIR)

# Phony target to avoid conflicts with file names
.PHONY: all clean
