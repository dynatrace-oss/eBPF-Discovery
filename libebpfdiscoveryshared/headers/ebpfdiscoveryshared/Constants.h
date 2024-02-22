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

#pragma once

#define DISCOVERY_BUFFER_MAX_DATA_SIZE 10240 // 10 KiB
#define DISCOVERY_MAX_SESSIONS 8192
#define DISCOVERY_EVENT_QUEUE_SIZE 512

#define DISCOVERY_MAX_HTTP_REQUEST_LENGTH DISCOVERY_BUFFER_MAX_DATA_SIZE
#define DISCOVERY_MIN_HTTP_REQUEST_LENGTH 16

#define DISCOVERY_LOG_MAX_FORMAT_LENGTH 128
#define DISCOVERY_LOG_MAX_MESSAGE_LENGTH DISCOVERY_LOG_MAX_FORMAT_LENGTH + 32
#define DISCOVERY_LOG_MAX_ARGS_COUNT 8

#define DISCOVERY_HANDLER_MAX_IOVLEN 3
