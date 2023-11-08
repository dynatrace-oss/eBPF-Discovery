from utils import discovered_service_has_clients, send_http_requests


def test_service_discovery(run_ebpf_discovery, run_http_service, http_server_port):
    base_url = "http://127.0.0.1:{}/".format(http_server_port)
    url = base_url + "some/url"
    requests_num = 5
    send_http_requests(url, requests_num)
    assert discovered_service_has_clients(run_ebpf_discovery, url, requests_num, 0)

    url = base_url + "other/url"
    requests_num = 10
    send_http_requests(url, requests_num)
    assert discovered_service_has_clients(run_ebpf_discovery, url, requests_num, 0)

    # TODO: uncomment when discovery handles X-Forwarded-For properly
    # url = base_url + "forwarded"
    # requests_num = 2
    # send_http_requests(url, requests_num, "1.2.3.4")
    # assert discovered_service_has_clients(run_ebpf_discovery, url, 0, requests_num)
