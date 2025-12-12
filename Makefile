CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET = camera_patcher
SRC = main.cpp

all: $(TARGET) fix_ptrace.sh

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)
	@echo ""
	@echo "✅ Compilation successful!"
	@echo ""
	@echo "Before running, fix ptrace_scope:"
	@echo "  ./fix_ptrace.sh"
	@echo ""
	@echo "Then run:"
	@echo "  sudo ./$(TARGET)"

fix_ptrace.sh:
	@echo '#!/bin/bash' > fix_ptrace.sh
	@echo 'echo "Checking ptrace_scope..."' >> fix_ptrace.sh
	@echo 'CURRENT=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)' >> fix_ptrace.sh
	@echo 'echo "Current value: $CURRENT"' >> fix_ptrace.sh
	@echo 'if [ "$CURRENT" != "0" ]; then' >> fix_ptrace.sh
	@echo '  echo "Setting ptrace_scope to 0..."' >> fix_ptrace.sh
	@echo '  sudo sysctl -w kernel.yama.ptrace_scope=0' >> fix_ptrace.sh
	@echo '  echo "✅ Done! Now run: sudo ./$(TARGET)"' >> fix_ptrace.sh
	@echo 'else' >> fix_ptrace.sh
	@echo '  echo "✅ Already set to 0"' >> fix_ptrace.sh
	@echo 'fi' >> fix_ptrace.sh
	@chmod +x fix_ptrace.sh

clean:
	rm -f $(TARGET) fix_ptrace.sh

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

run: $(TARGET)
	@echo "Checking ptrace_scope..."
	@bash -c 'if [ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)" != "0" ]; then echo "⚠️  Run ./fix_ptrace.sh first!"; exit 1; fi'
	sudo ./$(TARGET)

.PHONY: all clean install run
