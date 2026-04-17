CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -D_GNU_SOURCE
LIBS    = -lcurl -lpthread
TARGET  = authsec-shield-fanotify
SRC     = authsec_shield_fanotify.c

PREFIX       = /usr/local
SBIN_DIR     = $(PREFIX)/sbin
SYSTEMD_DIR  = /etc/systemd/system
CONFIG_DIR   = /etc/authsec-shield

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	@echo "Built: $(TARGET)"

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Installing $(TARGET) to $(SBIN_DIR)/..."
	install -m 755 $(TARGET) $(SBIN_DIR)/$(TARGET)
	@echo "Installing systemd unit..."
	install -m 644 authsec-shield-fanotify.service $(SYSTEMD_DIR)/authsec-shield-fanotify.service
	@echo "Creating config directory $(CONFIG_DIR)/..."
	mkdir -p $(CONFIG_DIR)
	@echo ""
	@echo "Enable and start with:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now authsec-shield-fanotify"

uninstall:
	systemctl stop authsec-shield-fanotify 2>/dev/null || true
	systemctl disable authsec-shield-fanotify 2>/dev/null || true
	rm -f $(SBIN_DIR)/$(TARGET)
	rm -f $(SYSTEMD_DIR)/authsec-shield-fanotify.service
	systemctl daemon-reload

# Quick test: check capabilities
check-caps:
	@if [ "$$(id -u)" -ne 0 ]; then \
	  echo "ERROR: fanotify permission events require root or CAP_SYS_ADMIN"; \
	  exit 1; \
	fi
	@echo "OK: running as root"
