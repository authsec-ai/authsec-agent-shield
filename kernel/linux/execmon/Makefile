CC      = gcc
CLANG   = clang
CFLAGS  = -O2 -Wall -Wextra -D_GNU_SOURCE
LIBS    = -lcurl -lpthread -lbpf -lelf -lz
TARGET  = authsec-shield-execmon
EBPF_SRC = authsec_execmon_ebpf.c
EBPF_OBJ = authsec_execmon_ebpf.o
MAIN_SRC = authsec_execmon.c

PREFIX      = /usr/local
SBIN_DIR    = $(PREFIX)/sbin
LIB_DIR     = $(PREFIX)/lib/authsec-shield
SYSTEMD_DIR = /etc/systemd/system
CONFIG_DIR  = /etc/authsec-shield

# Detect kernel version for BTF support
KERNEL_VERSION := $(shell uname -r | cut -d'.' -f1-2)
KERNEL_MAJOR   := $(shell uname -r | cut -d'.' -f1)
KERNEL_MINOR   := $(shell uname -r | cut -d'.' -f2)

.PHONY: all clean install install-artifacts uninstall check-deps

all: check-deps $(TARGET) $(EBPF_OBJ)

check-deps:
	@command -v clang  >/dev/null 2>&1 || { echo "ERROR: clang required (apt install clang)"; exit 1; }
	@command -v $(CC)  >/dev/null 2>&1 || { echo "ERROR: gcc required"; exit 1; }
	@pkg-config --exists libcurl 2>/dev/null || { echo "ERROR: libcurl-dev required"; exit 1; }
	@pkg-config --exists libbpf  2>/dev/null || { echo "ERROR: libbpf-dev required (apt install libbpf-dev)"; exit 1; }
	@echo "OK: all dependencies found"

$(EBPF_OBJ): $(EBPF_SRC) authsec_execmon_ebpf.h
	$(CLANG) -target bpf -O2 -g \
		-I/usr/include/bpf \
		-I/usr/include/linux \
		-D__TARGET_ARCH_x86 \
		-c $(EBPF_SRC) -o $@
	@echo "Built eBPF object: $@"

$(TARGET): $(MAIN_SRC) authsec_execmon_ebpf.h
	$(CC) $(CFLAGS) `pkg-config --cflags libbpf libcurl` \
		-o $@ $< \
		$(LIBS) `pkg-config --libs libbpf libcurl`
	@echo "Built daemon: $@"

clean:
	rm -f $(TARGET) $(EBPF_OBJ)

install-artifacts: all
	@echo "Installing exec monitor daemon artifacts..."
	install -d $(SBIN_DIR)
	install -d $(LIB_DIR)
	install -d $(CONFIG_DIR)
	install -m 755 $(TARGET)  $(SBIN_DIR)/$(TARGET)
	install -m 644 $(EBPF_OBJ) $(LIB_DIR)/authsec_execmon_ebpf.o
	install -m 644 authsec-shield-execmon.service $(SYSTEMD_DIR)/authsec-shield-execmon.service
	# Make daemon binary immutable — prevents deletion even by root unless chattr -i first
	chattr +i $(SBIN_DIR)/$(TARGET) || true
	@echo "Exec monitor artifacts installed. Service not started."

install: install-artifacts
	@echo ""
	@echo "Reloading systemd and enabling service..."
	systemctl daemon-reload
	systemctl enable --now authsec-shield-execmon
	@echo ""
	@echo "Exec monitor installed and running."
	@echo "ALL process executions on this machine are now intercepted."

uninstall:
	systemctl stop    authsec-shield-execmon 2>/dev/null || true
	systemctl disable authsec-shield-execmon 2>/dev/null || true
	chattr -i $(SBIN_DIR)/$(TARGET) 2>/dev/null || true
	rm -f $(SBIN_DIR)/$(TARGET)
	rm -f $(LIB_DIR)/authsec_execmon_ebpf.o
	rm -f $(SYSTEMD_DIR)/authsec-shield-execmon.service
	systemctl daemon-reload

check-running:
	@systemctl is-active authsec-shield-execmon && echo "Exec monitor: RUNNING" || echo "Exec monitor: STOPPED"
