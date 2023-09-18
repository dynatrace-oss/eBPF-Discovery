// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

namespace ebpfdiscovery {

template <typename KeyType, typename ValueType, typename HashType>
class LRUCache {
private:
	using ContainerItem = std::pair<KeyType, ValueType>;
	using ContainerType = boost::multi_index_container<
			ContainerItem,
			boost::multi_index::indexed_by<
					boost::multi_index::hashed_unique<boost::multi_index::member<ContainerItem, KeyType, &ContainerItem::first>, HashType>,
					boost::multi_index::sequenced<>>>;
	constexpr static int hashedIndex = 0;
	constexpr static int sequencedIndex = 1;

public:
	using iterator = typename ContainerType::template nth_index<hashedIndex>::type::iterator;

	LRUCache(size_t capacity) : capacity(capacity){};
	~LRUCache() = default;

	LRUCache(const LRUCache&) = delete;
	LRUCache& operator=(const LRUCache&) = delete;

	LRUCache(LRUCache&&) = default;
	LRUCache& operator=(LRUCache&&) = default;

	void insert(const KeyType& key, const ValueType& value) {
		auto& hashedContainer = getHashedContainer();
		auto it = hashedContainer.find(key);

		if (it == hashedContainer.end()) {
			auto& indexBySequence = getSequencedContainer();
			if (container.size() >= capacity) {
				indexBySequence.pop_back();
			}

			indexBySequence.push_front(std::make_pair(key, value));
		} else {
			relocateItemToBeginning(it);
			update(it, [&value](auto& originalValue) { originalValue = value; });
		}
	}

	iterator end() {
		return getHashedContainer().end();
	}

	iterator find(const KeyType& key) {
		auto& hashedContainer = getHashedContainer();
		auto it = hashedContainer.find(key);

		if (it == hashedContainer.end()) {
			return it;
		}

		relocateItemToBeginning(it);
		return it;
	}

	void erase(iterator it) {
		getHashedContainer().erase(it);
	}

	bool update(const iterator it, const std::function<void(ValueType&)>& modifier) {
		return getHashedContainer().modify(it, [&modifier](ContainerItem& item) { modifier(item.second); });
	}

private:
	auto& getHashedContainer() {
		return container.template get<hashedIndex>();
	}

	auto& getSequencedContainer() {
		return container.template get<sequencedIndex>();
	}

	void relocateItemToBeginning(iterator it) {
		auto& sequencedContainer = getSequencedContainer();
		sequencedContainer.relocate(sequencedContainer.begin(), container.template project<sequencedIndex>(it));
	}

	size_t capacity;
	ContainerType container;
};

} // namespace ebpfdiscovery
