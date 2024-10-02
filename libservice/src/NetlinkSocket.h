/*
 * Copyright 2024 Dynatrace LLC
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

#include <net/if.h>

namespace service {

class NetlinkSocket {
public:
	NetlinkSocket();
	~NetlinkSocket();

	ssize_t send(const msghdr* message, int flags) const;
	ssize_t receive(msghdr* message, int flags) const;

	explicit operator bool() const {
		return fd != -1;
	}

private:
	int fd;
};

} // namespace service
