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

#include <boost/json.hpp>
#include <boost/describe.hpp>
#include <string_view>

namespace boost::json {
	  template<typename T>
    void tag_invoke(json::value_from_tag, json::value& v, std::reference_wrapper<T> const& wrapped) {
        v = json::value_from(wrapped.get());
    }
} // namespace boost::json

template<typename T>
boost::json::object toJson(std::string_view key, T convertibleValue) {
	boost::json::object outJson{};
	outJson[key] = boost::json::value_from(convertibleValue);
	return outJson; 
}
