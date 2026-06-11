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
#include <gmock/gmock.h>

#include "ebpfdiscovery/LibBpfInterface.h"

class LibBpfInterfaceMock : public ebpfdiscovery::LibBpfInterface {
public:
	MOCK_METHOD(int, getMapFd, (const struct bpf_map* map), (override));
	MOCK_METHOD(int, pollEvents, (ring_buffer*, int), (override));
	MOCK_METHOD(void, freeRingBuffer, (ring_buffer*), (override));
	MOCK_METHOD(ring_buffer*, createRingBuffer, (int, ring_buffer_sample_fn, void*, const ring_buffer_opts*), (override));
	MOCK_METHOD(bpf_link*, attachProgram, (const struct bpf_program*), (override));
};
