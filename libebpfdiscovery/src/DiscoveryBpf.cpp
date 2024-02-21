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

void DiscoveryBpf::attachSyscallProbes() {
	attachKprobe(&skel->links.kprobeSysAccept, skel->progs.kprobeSysAccept, SYS_PREFIX "sys_accept");
	attachKretprobe(&skel->links.kretprobeSysAccept, skel->progs.kretprobeSysAccept, SYS_PREFIX "sys_accept");
	attachKprobe(&skel->links.kprobeSysAccept4, skel->progs.kprobeSysAccept4, SYS_PREFIX "sys_accept4");
	attachKretprobe(&skel->links.kretprobeSysAccept4, skel->progs.kretprobeSysAccept4, SYS_PREFIX "sys_accept4");
	attachKprobe(&skel->links.kprobeSysRead, skel->progs.kprobeSysRead, SYS_PREFIX "sys_read");
	attachKretprobe(&skel->links.kretprobeSysRead, skel->progs.kretprobeSysRead, SYS_PREFIX "sys_read");
	attachKprobe(&skel->links.kprobeSysRecv, skel->progs.kprobeSysRecv, SYS_PREFIX "sys_recv");
	attachKretprobe(&skel->links.kretprobeSysRecv, skel->progs.kretprobeSysRecv, SYS_PREFIX "sys_recv");
	attachKprobe(&skel->links.kprobeSysRecvfrom, skel->progs.kprobeSysRecvfrom, SYS_PREFIX "sys_recvfrom");
	attachKretprobe(&skel->links.kretprobeSysRecvfrom, skel->progs.kretprobeSysRecvfrom, SYS_PREFIX "sys_recvfrom");
	attachKprobe(&skel->links.kprobeSysClose, skel->progs.kprobeSysClose, SYS_PREFIX "sys_close");
}

void DiscoveryBpf::attachKprobe(bpf_link** link, bpf_program* prog, const std::string& funcName) {
	*link = bpf_program__attach_kprobe(prog, false, funcName.c_str());
	if (*link == nullptr) {
		LOG_WARN("Failed to attach kprobe for {}.", funcName);
	}
}

void DiscoveryBpf::attachKretprobe(bpf_link** link, bpf_program* prog, const std::string& funcName) {
	*link = bpf_program__attach_kprobe(prog, true, funcName.c_str());
	if (*link == nullptr) {
		LOG_WARN("Failed to attach kretprobe for {}.", funcName);
	}
}

void DiscoveryBpf::attachLibSSLProbes() {
	attachUprobeToLibFunc(&skel->links.uprobeSSLRead, skel->progs.uprobeSSLRead, "libssl.so", "SSL_read");
	attachUretprobeToLibFunc(&skel->links.uretprobeSSLReadOpenSSL, skel->progs.uretprobeSSLReadOpenSSL, "libssl.so", "SSL_read");

	attachUprobeToLibFunc(&skel->links.uprobeSSLRead, skel->progs.uprobeSSLRead, "libssl.so.3", "SSL_read");
	attachUretprobeToLibFunc(&skel->links.uretprobeSSLReadOpenSSL3_0, skel->progs.uretprobeSSLReadOpenSSL3_0, "libssl.so.3", "SSL_read");
	attachUprobeToLibFunc(&skel->links.uprobeSSLRead, skel->progs.uprobeSSLRead, "libssl3.so", "SSL_read");
	attachUretprobeToLibFunc(&skel->links.uretprobeSSLReadOpenSSL3_0, skel->progs.uretprobeSSLReadOpenSSL3_0, "libssl3.so", "SSL_read");

	attachUprobeToLibFunc(&skel->links.uprobeSSLRead, skel->progs.uprobeSSLRead, "libssl.so.1", "SSL_read");
	attachUretprobeToLibFunc(&skel->links.uretprobeSSLReadOpenSSL3_0, skel->progs.uretprobeSSLReadOpenSSL1_1_1, "libssl.so.1", "SSL_read");
	attachUprobeToLibFunc(&skel->links.uprobeSSLRead, skel->progs.uprobeSSLRead, "libssl1.so", "SSL_read");
	attachUretprobeToLibFunc(&skel->links.uretprobeSSLReadOpenSSL3_0, skel->progs.uretprobeSSLReadOpenSSL1_1_1, "libssl1.so", "SSL_read");
}

void DiscoveryBpf::attachUprobeToLibFunc(bpf_link** link, bpf_program* prog, const std::string& libName, const std::string& funcName) {
	LIBBPF_OPTS(bpf_uprobe_opts, uprobeOpts);
	uprobeOpts.func_name = funcName.c_str();
	uprobeOpts.retprobe = false;
	*link = bpf_program__attach_uprobe_opts(prog, -1, libName.c_str(), 0, &uprobeOpts);
	if (link == nullptr) {
		LOG_ERROR("Failed to attach uprobe for {} {}.", libName, funcName);
	}
}

void DiscoveryBpf::attachUretprobeToLibFunc(bpf_link** link, bpf_program* prog, const std::string& libName, const std::string& funcName) {
	LIBBPF_OPTS(bpf_uprobe_opts, uprobeOpts);
	uprobeOpts.func_name = funcName.c_str();
	uprobeOpts.retprobe = true;
	*link = bpf_program__attach_uprobe_opts(prog, -1, libName.c_str(), 0, &uprobeOpts);
	if (link == nullptr) {
		LOG_ERROR("Failed to attach uretprobe for {} {}.", libName, funcName);
	}
}

} // namespace ebpfdiscovery
