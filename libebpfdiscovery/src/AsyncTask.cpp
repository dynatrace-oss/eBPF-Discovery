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

#include "ebpfdiscovery/AsyncTask.h"

namespace ebpfdiscovery {

void AsyncTask::stop() {
	stopRequested = true;
	cv.notify_all();
}

std::future<void> AsyncTask::startAsync(const std::chrono::milliseconds interval, std::function<void()> func) {
	return std::async(std::launch::async, [this, interval, func = std::move(func)]() {
		while (!stopRequested) {
			func();
			//short circuit to avoid waiting the whole interval when func calls cv.notify_all (e.g. via stop)
			if (stopRequested) {
				break;
			}
			{
				std::unique_lock ul(mutex);
				cv.wait_for(ul, interval, [this] { return stopRequested.load(); });
			}
		}
	});
}

}
