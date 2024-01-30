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

#include "Formatting.h"

#include <gtest/gtest.h>

#include <cstdarg>
#include <string>

using logging::vaFormat;

TEST(VaFormatTest, testFormat) {
	const std::string expected{"Hello, World!"};
	const std::string actual{vaFormat("Hello, %s!", "World")};
	ASSERT_EQ(actual, expected);
}

TEST(VaFormatTest, testMultipleFormat) {
	const std::string expected{"Hello, World! 1 + 2 = 3"};
	const std::string actual{vaFormat("Hello, %s! %d %c %d %c %d", "World", 1, '+', 2, '=', 3)};
	ASSERT_EQ(actual, expected);
}

TEST(VaFormatTest, testLongFormat) {
	const std::string longString(300, 'Z');
	const std::string expected{longString + " Hello, World!"};
	const std::string format{longString + " Hello, %s!"};
	const std::string actual = vaFormat(format.c_str(), "World");
	ASSERT_EQ(actual, expected);
}

TEST(VaFormatTest, test256Format) {
	const std::string longString(254, 'Z');
	const std::string expected{longString + "32"};
	const std::string format{longString + "%d"};
	const std::string actual = vaFormat(format.c_str(), 32);
	ASSERT_EQ(actual, expected);
}

TEST(VaFormatTest, test255Format) {
	const std::string longString(254, 'Z');
	const std::string expected{longString + "3"};
	const std::string format{longString + "%d"};
	const std::string actual = vaFormat(format.c_str(), 3);
	ASSERT_EQ(actual, expected);
}
