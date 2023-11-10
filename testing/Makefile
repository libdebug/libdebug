# Makefile for building individual .c files in srcs folder

# Compiler and compiler flags
CC := gcc
CFLAGS := -Wall -Wextra -std=gnu11

# Directories
SRC_DIR := srcs
BIN_DIR := binaries

# Source files
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

# Target executables (one for each source file)
TARGETS := $(patsubst $(SRC_DIR)/%.c,$(BIN_DIR)/%,$(SRC_FILES))

# Default target to build all executables
all: $(TARGETS)

# Rule to build each executable
$(BIN_DIR)/%: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@

# Create the binaries directory if it doesn't exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean rule to remove compiled files
clean:
	rm -rf $(BIN_DIR)

# Phony target to avoid conflicts with file names
.PHONY: all clean
