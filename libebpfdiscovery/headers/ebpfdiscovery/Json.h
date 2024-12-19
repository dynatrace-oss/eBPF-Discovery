/* Copyright 2023 Dynatrace LLC
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

#include <boost/json.hpp>
#include <chrono>
#include <string_view>
#include <unordered_map>

namespace boost::json {
template <typename T>
void tag_invoke(json::value_from_tag, json::value& v, const std::reference_wrapper<T>& wrapped) {
	v = json::value_from(wrapped.get());
}
} // namespace boost::json

namespace boost::json::ext {

void print(std::ostream& os, const boost::json::value& jv) {
	switch (jv.kind()) {
	case json::kind::object: {
		const auto& obj = jv.get_object();
		if (!obj.empty()) {
			os << "{";
			for (auto it = obj.begin(); it != obj.end(); ++it) {
				const auto val = it->value();
				if (val.is_null() || (val.is_string() && (val.get_string().size() == 0))) {
					continue;
				}
				if (it != obj.begin()) {
					os << ",";
				}
				os << json::serialize(it->key()) << ":";
				print(os, val);
			}
			os << "}";
		}
		break;
	}

	case json::kind::array: {
		const auto& arr = jv.get_array();
		if (!arr.empty()) {
			os << "[";
			for (auto it = arr.begin(); it != arr.end(); ++it) {
				if (it != arr.begin()) {
					os << ",";
				}
				print(os, *it);
			}
		}
		os << "]";
		break;
	}
	default:
		os << jv;
	}
}
} // namespace boost::json::ext
