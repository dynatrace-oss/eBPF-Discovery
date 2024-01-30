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

#include "ebpfdiscovery/LRUCache.h"

#include <gtest/gtest.h>

#include <functional>
#include <string>

using ebpfdiscovery::LRUCache;

TEST(LRUCacheTest, testInsertAndFind) {
	LRUCache<int, std::string, std::hash<int>> cache(3);

	cache.insert(1, "one");
	cache.insert(2, "two");
	cache.insert(3, "three");

	EXPECT_EQ(cache.find(1)->second, "one");
	EXPECT_EQ(cache.find(2)->second, "two");
	EXPECT_EQ(cache.find(3)->second, "three");
}

TEST(LRUCacheTest, testErase) {
	LRUCache<int, std::string, std::hash<int>> cache(3);

	cache.insert(1, "one");
	cache.insert(2, "two");
	cache.insert(3, "three");

	auto it = cache.find(2);
	cache.erase(it);

	EXPECT_EQ(cache.find(1)->second, "one");
	EXPECT_EQ(cache.find(2), cache.end());
	EXPECT_EQ(cache.find(3)->second, "three");
}

TEST(LRUCacheTest, testInsertExistingKey) {
	LRUCache<int, std::string, std::hash<int>> cache(3);

	cache.insert(1, "one");
	cache.insert(2, "two");
	cache.insert(3, "three");
	cache.insert(2, "two_updated");

	EXPECT_EQ(cache.find(1)->second, "one");
	EXPECT_EQ(cache.find(2)->second, "two_updated");
	EXPECT_EQ(cache.find(3)->second, "three");
}

TEST(LRUCacheTest, testUpdate) {
	LRUCache<int, std::string, std::hash<int>> cache(3);

	cache.insert(1, "one");
	cache.insert(2, "two");
	cache.insert(3, "three");

	auto it = cache.find(2);
	cache.update(it, [](auto& val) { val.append("_updated"); });

	EXPECT_EQ(cache.find(1)->second, "one");
	EXPECT_EQ(cache.find(2)->second, "two_updated");
	EXPECT_EQ(cache.find(3)->second, "three");
}

TEST(LRUCacheTest, testInsertBeyondCapacity) {
	LRUCache<int, std::string, std::hash<int>> cache(3);

	cache.insert(1, "one");
	cache.insert(2, "two");
	cache.insert(3, "three");
	cache.insert(4, "four");
	cache.insert(5, "five");

	EXPECT_EQ(cache.find(1), cache.end());
	EXPECT_EQ(cache.find(2), cache.end());
	EXPECT_EQ(cache.find(3)->second, "three");
	EXPECT_EQ(cache.find(4)->second, "four");
	EXPECT_EQ(cache.find(5)->second, "five");
}
