from utils import discovered_service_has_clients, send_http_requests


def test_service_discovery(run_ebpf_discovery, http_service):
    url = http_service + "some/url"
    requests_num = 5
    send_http_requests(url, requests_num)
    assert discovered_service_has_clients(run_ebpf_discovery, url, requests_num, 0)

    url = http_service + "other/url"
    requests_num = 10
    send_http_requests(url, requests_num)
    assert discovered_service_has_clients(run_ebpf_discovery, url, requests_num, 0)
