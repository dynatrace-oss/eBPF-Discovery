// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <bpf/libbpf.h>

#include <atomic>
#include <thread>

namespace ebpfdiscovery::bpflogging {

perf_buffer* setupLogging(int logPerfBufFd);
int fetchAndLog(perf_buffer* logBuf);
void closeLogging(perf_buffer* logBuf);

} // namespace ebpfdiscovery::bpflogging
