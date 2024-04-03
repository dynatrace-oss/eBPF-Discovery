/*
 * Copyright 2023 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ebpfdiscovery/DiscoveryBpf.h"

#include "ebpfdiscoveryshared/SysPrefixMacro.h"
#include "logging/Logger.h"

#include <fmt/core.h>

extern "C" {
#include "../../third_party/bcc/libbpf-tools/btf_helpers.h"
}

namespace ebpfdiscovery {

void DiscoveryBpf::load() {
	LOG_DEBUG("Loading BPF program.");

	{
		LIBBPF_OPTS(bpf_object_open_opts, newOpenOpts);
		openOpts = newOpenOpts;
	}

	LOG_TRACE("Fetching BTF for CO-RE.");
	if (const auto res{ensure_core_btf(&openOpts)}) {
		throw std::runtime_error("Failed to fetch necessary BTF for CO-RE: " + std::string(strerror(-res)));
	}
	coreEnsured = true;

	LOG_TRACE("Opening Discovery BPF object.");
	skel = discovery_bpf__open_opts(&openOpts);
	if (skel == nullptr) {
		throw std::runtime_error("Failed to open BPF object.");
	}

	LOG_TRACE("Loading Discovery BPF program.");
	if (const auto res{discovery_bpf__load(skel)}) {
		throw std::runtime_error("Failed to load BPF object: " + std::to_string(res));
	}

	LOG_TRACE("Attaching Discovery BPF program.");
	attachSyscallProbes();
	attachLibSSLProbes();
}

void DiscoveryBpf::unload() {
	if (skel != nullptr) {
		discovery_bpf__destroy(skel);
		skel = nullptr;
	}

	if (coreEnsured) {
		cleanup_core_btf(&openOpts);
		coreEnsured = false;
	}
}

DiscoveryBpfFds DiscoveryBpf::getFds() {
	return {
			.globalStateMap = bpf_map__fd(skel->maps.globalStateMap),
			.eventsToUserspaceQueueMap = bpf_map__fd(skel->maps.eventsToUserspaceQueueMap),
			.savedBuffersMap = bpf_map__fd(skel->maps.savedBuffersMap),
			.trackedSessionsMap = bpf_map__fd(skel->maps.trackedSessionsMap),
	};
}

int DiscoveryBpf::getLogPerfBufFd() {
	return bpf_map__fd(skel->maps.logEventsPerfMap);
}

static bpf_link* attachKprobe(bpf_program* prog, const std::string& funcName) {
	auto link{bpf_program__attach_kprobe(prog, false, funcName.c_str())};
	if (link == nullptr) {
		LOG_WARN("Failed to attach kprobe for {}.", funcName);
	}
	return link;
}

static bpf_link* attachKretprobe(bpf_program* prog, const std::string& funcName) {
	auto link{bpf_program__attach_kprobe(prog, true, funcName.c_str())};
	if (link == nullptr) {
		LOG_WARN("Failed to attach kretprobe for {}.", funcName);
	}
	return link;
}

static bpf_link* attachUprobeToLibFunc(bpf_program* prog, const std::string& libName, const std::string& funcName) {
	LIBBPF_OPTS(bpf_uprobe_opts, uprobeOpts);
	uprobeOpts.func_name = funcName.c_str();
	uprobeOpts.retprobe = false;
	auto link{bpf_program__attach_uprobe_opts(prog, -1, libName.c_str(), 0, &uprobeOpts)};
	if (link == nullptr) {
		LOG_ERROR("Failed to attach uprobe for {} {}.", libName, funcName);
	}
	return link;
}

static bpf_link* attachUretprobeToLibFunc(bpf_program* prog, const std::string& libName, const std::string& funcName) {
	LIBBPF_OPTS(bpf_uprobe_opts, uprobeOpts);
	uprobeOpts.func_name = funcName.c_str();
	uprobeOpts.retprobe = true;
	auto link{bpf_program__attach_uprobe_opts(prog, -1, libName.c_str(), 0, &uprobeOpts)};
	if (link == nullptr) {
		LOG_ERROR("Failed to attach uretprobe for {} {}.", libName, funcName);
	}
	return link;
}

void DiscoveryBpf::attachSyscallProbes() {
	skel->links.kprobeSysAccept = attachKprobe(skel->progs.kprobeSysAccept, SYS_PREFIX "sys_accept");
	skel->links.kretprobeSysAccept = attachKretprobe(skel->progs.kretprobeSysAccept, SYS_PREFIX "sys_accept");
	skel->links.kprobeSysAccept4 = attachKprobe(skel->progs.kprobeSysAccept4, SYS_PREFIX "sys_accept4");
	skel->links.kretprobeSysAccept4 = attachKretprobe(skel->progs.kretprobeSysAccept4, SYS_PREFIX "sys_accept4");
	skel->links.kprobeSysRead = attachKprobe(skel->progs.kprobeSysRead, SYS_PREFIX "sys_read");
	skel->links.kretprobeSysRead = attachKretprobe(skel->progs.kretprobeSysRead, SYS_PREFIX "sys_read");
	skel->links.kprobeSysRecv = attachKprobe(skel->progs.kprobeSysRecv, SYS_PREFIX "sys_recv");
	skel->links.kretprobeSysRecv = attachKretprobe(skel->progs.kretprobeSysRecv, SYS_PREFIX "sys_recv");
	skel->links.kprobeSysRecvfrom = attachKprobe(skel->progs.kprobeSysRecvfrom, SYS_PREFIX "sys_recvfrom");
	skel->links.kretprobeSysRecvfrom = attachKretprobe(skel->progs.kretprobeSysRecvfrom, SYS_PREFIX "sys_recvfrom");
	skel->links.kprobeSysClose = attachKprobe(skel->progs.kprobeSysClose, SYS_PREFIX "sys_close");
}

void DiscoveryBpf::attachLibSSLProbes() {
	skel->links.uprobeSSLReadOpenSSL = attachUprobeToLibFunc(skel->progs.uprobeSSLReadOpenSSL, "libssl.so", "SSL_read");
	skel->links.uretprobeSSLReadOpenSSL = attachUretprobeToLibFunc(skel->progs.uretprobeSSLReadOpenSSL, "libssl.so", "SSL_read");
	skel->links.uprobeSSLReadExOpenSSL = attachUprobeToLibFunc(skel->progs.uprobeSSLReadExOpenSSL, "libssl.so", "SSL_read_ex");
	skel->links.uretprobeSSLReadExOpenSSL = attachUretprobeToLibFunc(skel->progs.uretprobeSSLReadExOpenSSL, "libssl.so", "SSL_read_ex");
	skel->links.uprobeSSLPendingOpenSSL = attachUprobeToLibFunc(skel->progs.uprobeSSLPendingOpenSSL, "libssl.so", "SSL_pending");
	skel->links.uretprobeSSLPendingOpenSSL = attachUretprobeToLibFunc(skel->progs.uretprobeSSLPendingOpenSSL, "libssl.so", "SSL_pending");
}

} // namespace ebpfdiscovery
