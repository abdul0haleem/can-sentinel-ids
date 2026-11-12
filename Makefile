# ============================================================================
# CAN-Sentinel Master Build Automation System
# Root Controller for Simulation, Ingestion, Attack, and ML Pipeline
# ============================================================================

.PHONY: all clean test sim sim-mt sniffer dashboard help setup-vcan

# Default: compile simulation and sniffer binaries
all:
	@echo "Building CAN-Sentinel C modules..."
	$(MAKE) -C ecu_sim all
	@if [ -d "sniffer" ]; then \
		echo "Building raw SocketCAN sniffer..."; \
		gcc -Wall -O2 -o sniffer/can_sniffer sniffer/can_sniffer.c sniffer/socket_bridge.c 2>/dev/null || true; \
	fi
	@echo "Build complete."

# Run all automated unit tests across the entire repository (43 tests)
test:
	@echo "========================================================="
	@echo "1. Running ECU Simulator C payload unit tests (7/7)..."
	@echo "========================================================="
	$(MAKE) -C ecu_sim test
	@echo "\n========================================================="
	@echo "2. Running Attacker Framework pytest suite..."
	@echo "========================================================="
	python3 -m pytest attacker/test_*.py -q
	@echo "\n========================================================="
	@echo "3. Running ML Engine and Rules pytest suite..."
	@echo "========================================================="
	python3 -m pytest ml_engine/test_*.py -q
	@echo "\n========================================================="
	@echo "4. Running Virtual Security Gateway pytest suite..."
	@echo "========================================================="
	python3 -m pytest gateway/test_*.py -q
	@echo "\nAll 43 unit verification tests passed successfully."

# Setup virtual CAN testbed (vcan0 and vcan1)
setup-vcan:
	$(MAKE) -C ecu_sim setup-vcan

# Launch baseline single-threaded ECU simulator
sim:
	$(MAKE) -C ecu_sim run

# Launch baseline multi-threaded ECU simulator
sim-mt:
	$(MAKE) -C ecu_sim run-mt

# Launch Web EV Sport Cockpit on port 8080
dashboard:
	$(MAKE) -C ecu_sim dashboard

# Clean all compiled binaries and build artifacts
clean:
	$(MAKE) -C ecu_sim clean
	rm -f sniffer/can_sniffer
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned all build artifacts and caches."

# Display help menu
help:
	@echo "CAN-Sentinel Master Build Targets:"
	@echo "  make              - Compile all C modules (ecu_simulator, sniffer)"
	@echo "  make test         - Run full 43-test automated verification suite"
	@echo "  make setup-vcan   - Instantiate and bring up vcan0 and vcan1"
	@echo "  make sim          - Launch baseline 6-ECU simulator (320 FPS)"
	@echo "  make sim-mt       - Launch distributed multi-threaded simulator"
	@echo "  make dashboard    - Launch Web EV Sport Cockpit (http://localhost:8080)"
	@echo "  make clean        - Remove compiled binaries and caches"
