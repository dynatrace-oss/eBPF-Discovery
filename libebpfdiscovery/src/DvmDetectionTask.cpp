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

#include "ebpfdiscovery/DvmDetectionTask.h"

namespace ebpfdiscovery {

DvmDetectionTask::~DvmDetectionTask() {
	shutdown();
}

void DvmDetectionTask::start(const bpf_object_open_opts& loadOptions, std::chrono::seconds dvmInterval) {
	dvmInstance.load(loadOptions);
	dvmFuture = startAsync(std::chrono::milliseconds{dvmInterval}, [this]() {
		dvmInstance.collectAndOutput();
	});
}

void DvmDetectionTask::shutdown() {
	stop();
	waitForFinish();
	dvmInstance.unload();
}

void DvmDetectionTask::waitForFinish() {
	if (dvmFuture.valid()) {
		dvmFuture.wait();
	}
}

} // namespace ebpfdiscovery
