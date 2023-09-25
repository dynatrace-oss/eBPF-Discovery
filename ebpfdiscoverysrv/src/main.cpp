// SPDX-License-Identifier: GPL-2.0

#include "ebpfdiscovery/Discovery.h"

#include <bpf/libbpf.h>

#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>

static ebpfdiscovery::Discovery discoveryInstance;

std::atomic<bool> isShuttingDown;

static void handleUnixExitSignal(int signo) {
	if (isShuttingDown) {
		return;
	}
	isShuttingDown = true;

	discoveryInstance.stopRun();
}

void setupUnixSignalHandlers() {
	struct sigaction action {};
	action.sa_handler = handleUnixExitSignal;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGTERM, &action, nullptr);
	sigaction(SIGPIPE, &action, nullptr);
}

static int libbpfPrintFn(enum libbpf_print_level level, const char* format, va_list args) {
#ifdef DEBUG
	return vfprintf(stderr, format, args);
#else
	return 0;
#endif
}

void setupLibbpf() {
	libbpf_set_print(libbpfPrintFn);
}

int main(int argc, char** argv) {
	setupLibbpf();
	setupUnixSignalHandlers();

	try {
		discoveryInstance.load();
	} catch (const std::runtime_error& e) {
		std::cerr << "Couldn't load BPF program: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	if (discoveryInstance.run() != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
