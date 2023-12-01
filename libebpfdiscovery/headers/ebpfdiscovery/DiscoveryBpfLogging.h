// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <bpf/libbpf.h>

#include <atomic>
#include <thread>

namespace ebpfdiscovery::bpflogging {

perf_buffer* init(int logPerfBufFd);
void stop(perf_buffer* logBuf);

int fetchAndLog(perf_buffer* logBuf);

} // namespace ebpfdiscovery::bpflogging
