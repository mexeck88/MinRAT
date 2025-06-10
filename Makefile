# Build C files for Server

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -pthread -Iinclude

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

SERVER_SRC = $(SRC_DIR)/server.c
SERVER_OBJ = $(BUILD_DIR)/server.o
OPERATIONS_SRC = $(SRC_DIR)/operations.c
OPERATIONS_OBJ = $(BUILD_DIR)/operations.o

SERVER_BIN = $(BIN_DIR)/capstone

all: $(SERVER_BIN)

$(SERVER_BIN): $(SERVER_OBJ) $(OPERATIONS_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# compile server.c and operations.c to object files
$(SERVER_OBJ): $(SERVER_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OPERATIONS_OBJ): $(OPERATIONS_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean
# End of Makefile