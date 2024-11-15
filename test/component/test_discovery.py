# Copyright 2023 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from utils import discovered_service_has_expected_clients, send_http_requests
import pytest


def test_multiple_requests_to_local_service(run_ebpf_discovery, run_http_service):
    url = run_http_service + "/some/url"
    requests_num = 5
    send_http_requests(url, requests_num)
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=requests_num,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

def test_request_forwarded_to_private_ip(run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "10.0.0.1:5001")
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize("client_ip_header_key, expected_external",
                         [("rproxy_remote_address", 1), ("X-Forwarded-For", 1), ("True-Client-IP", 1),
                          ("X-Client-Ip", 1), ("X-Http-Client-Ip", 1)])
def test_request_forwarded_to_public_ip(run_ebpf_discovery, run_http_service, client_ip_header_key, expected_external):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.1.57:8080", client_ip_header_key)
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=expected_external,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

def test_request_multiple_headers_private_ip_first(run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.1.57:8080", "rproxy_remote_address", {"x-forwarded-for" : "127.0.0.1:8080"})
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

def test_request_multiple_headers_public_ip_first(run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "127.0.0.1:8080", "x-forwarded-for", {"rproxy_remote_address" : "113.56.1.57:8080"})
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=1,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('bridge', 'br0', '112.34.0.13', 16)]], indirect=True)
def test_request_forwarded_to_local_bridge_with_public_ip(network_interfaces, run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "112.34.0.13:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('bridge', 'br0', '112.34.0.13', 16)]], indirect=True)
def test_request_forwarded_to_public_ip_matching_local_bridge_mask(network_interfaces, run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "112.34.1.28:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth15', '113.56.3.22', 16)]], indirect=True)
def test_request_forwarded_to_local_interface_with_public_ip(network_interfaces, run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.3.22:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth16', '113.56.3.22', 24)]], indirect=True)
def test_request_forwarded_to_public_ip_not_matching_local_interface_mask(network_interfaces, run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.1.57:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=1,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth17', '2001:db8:85a3::8a2e:370:7336', 64)]], indirect=True)
def test_request_forwarded_to_public_ipv6_matching_local_network_mask(network_interfaces, run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "2001:0db8:85a3:0000:0000:0000:0000:0000")
    send_http_requests(url, 1, "[2001:0db8:85a3::]:420")
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=2,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth18', '2001:db8:85a3::8a2e:370:7337', 64)]], indirect=True)
def test_request_forwarded_to_public_ipv6_not_matching_local_interface_mask(network_interfaces, run_ebpf_discovery, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "2001:0db8:85a3:0001:0000:0000:0000:0000")
    send_http_requests(url, 1, "[2001:0db8:85a3:0001::]:12345")
    send_http_requests(url, 1, "2001:0db8:85a2:ffff:ffff:ffff:ffff:ffff")
    send_http_requests(url, 1, "[2001:0db8:85a2:ffff:ffff:ffff:ffff:ffff]:111")
    assert discovered_service_has_expected_clients(run_ebpf_discovery, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=4,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

def test_multiple_requests_to_local_service(run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/some/url"
    requests_num = 5
    send_http_requests(url, requests_num)
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=requests_num,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

def test_request_forwarded_to_private_ip(run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "10.0.0.1:5001")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize("client_ip_header_key, expected_external",
                         [("rproxy_remote_address", 1), ("X-Forwarded-For", 1), ("True-Client-IP", 1),
                          ("X-Client-Ip", 1), ("X-Http-Client-Ip", 1)])
def test_request_forwarded_to_public_ip(run_ebpf_discovery_with_network_counters, run_http_service, client_ip_header_key, expected_external):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.1.57:8080", client_ip_header_key)
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=expected_external,
                                                   expected_external_ipv4_16_networks=1,
                                                   expected_external_ipv4_24_networks=1,
                                                   expected_external_ipv6_networks=0)

def test_request_multiple_headers_private_ip_first(run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.1.57:8080", "rproxy_remote_address", {"x-forwarded-for" : "127.0.0.1:8080"})
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

def test_request_multiple_headers_public_ip_first(run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "127.0.0.1:8080", "x-forwarded-for", {"rproxy_remote_address" : "113.56.1.57:8080"})
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=1,
                                                   expected_external_ipv4_16_networks=1,
                                                   expected_external_ipv4_24_networks=1,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('bridge', 'br1', '112.34.0.13', 16)]], indirect=True)
def test_request_forwarded_to_local_bridge_with_public_ip(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "112.34.0.13:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('bridge', 'br1', '112.34.0.13', 16)]], indirect=True)
def test_request_forwarded_to_public_ip_matching_local_bridge_mask(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "112.34.1.28:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth17', '113.56.3.22', 16)]], indirect=True)
def test_request_forwarded_to_local_interface_with_public_ip(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.3.22:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth18', '113.56.3.22', 16)]], indirect=True)
def test_request_forwarded_to_public_ip_matching_local_interface_mask(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "113.56.1.57:8080")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=1,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth19', '2001:db8:85a3::8a2e:370:7336', 64)]], indirect=True)
def test_request_forwarded_to_public_ipv6_matching_local_network_mask(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "2001:0db8:85a3:0000:0000:0000:0000:0000")
    send_http_requests(url, 1, "[2001:0db8:85a3::]:420")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=2,
                                                   expected_external_clients=0,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth20', '2001:db8:85a3::8a2e:370:7337', 64)]], indirect=True)
def test_request_forwarded_to_public_ipv6_not_matching_local_interface_mask(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "2001:0db8:85a3:0001:0000:0000:0000:0000")
    send_http_requests(url, 1, "[2001:0db8:85a3:0001::]:12345")
    send_http_requests(url, 1, "2001:0db8:85a2:ffff:ffff:ffff:ffff:ffff")
    send_http_requests(url, 1, "[2001:0db8:85a2:ffff:ffff:ffff:ffff:ffff]:111")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=4,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=2)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth21', '113.56.3.22', 16)]], indirect=True)
def test_request_forwarded_to_public_ipv4_network_counters(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "172.143.4.5")
    send_http_requests(url, 1, "172.143.6.89")
    send_http_requests(url, 1, "172.199.45.55")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=3,
                                                   expected_external_ipv4_16_networks=2,
                                                   expected_external_ipv4_24_networks=3,
                                                   expected_external_ipv6_networks=0)

@pytest.mark.parametrize('network_interfaces', [[('dummy', 'eth22', '2001:db8:85a3::8a2e:370:7337', 64)]], indirect=True)
def test_request_forwarded_to_public_ipv6_network_counters(network_interfaces, run_ebpf_discovery_with_network_counters, run_http_service):
    url = run_http_service + "/forwarded"
    send_http_requests(url, 1, "1234:2345:3456:4567:5678:6789:7890:8901")
    send_http_requests(url, 1, "2001:4860:4860:0000:0000:0000:0000:8888")
    assert discovered_service_has_expected_clients(run_ebpf_discovery_with_network_counters, url,
                                                   expected_internal_clients=0,
                                                   expected_external_clients=2,
                                                   expected_external_ipv4_16_networks=0,
                                                   expected_external_ipv4_24_networks=0,
                                                   expected_external_ipv6_networks=2)
