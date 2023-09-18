// SPDX-License-Identifier: Apache-2.0
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
