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
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <functional>
#include <future>
#include <mutex>

namespace ebpfdiscovery {

struct AsyncTask {
protected:
	virtual ~AsyncTask() = default;

	void stop();
	std::future<void> startAsync(std::chrono::milliseconds interval, std::function<void()> func);

	std::atomic<bool> stopRequested = false;
	std::mutex mutex;
	std::condition_variable cv;
};

}
