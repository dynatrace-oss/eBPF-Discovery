/*
* Copyright 2026 Dynatrace LLC
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

#pragma once
#include <bpf/libbpf.h>

namespace ebpfdiscovery {

class LibBpfInterface {
public:
	virtual ~LibBpfInterface() = default;

	virtual int getMapFd(const struct bpf_map* map) {
		return bpf_map__fd(map);
	}
	virtual int pollEvents(ring_buffer *rb, int timeout_ms) {
		return ring_buffer__poll(rb, 0);
	}
	virtual void freeRingBuffer(ring_buffer *rb) {
		ring_buffer__free(rb);
	}
	virtual ring_buffer* createRingBuffer(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx, const ring_buffer_opts *opts) {
		return ring_buffer__new(map_fd, sample_cb, ctx, opts);
	}
	virtual bpf_link* attachProgram(const struct bpf_program* prog) {
		return bpf_program__attach(prog);
	}
};

}
