// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <bpf/libbpf.h>

#include <atomic>
#include <thread>

namespace ebpfdiscovery::bpflogging {

perf_buffer* setup(int logPerfBufFd);
int fetchAndLog(perf_buffer* logBuf);
void close(perf_buffer* logBuf);

} // namespace ebpfdiscovery::bpflogging
