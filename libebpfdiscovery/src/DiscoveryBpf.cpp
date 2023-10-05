// SPDX-License-Identifier: Apache-2.0
#include "ebpfdiscovery/DiscoveryBpf.h"

namespace ebpfdiscovery {

DiscoveryBpf::DiscoveryBpf(discovery_bpf* skel) : skel(skel) {
}

} // namespace ebpfdiscovery
