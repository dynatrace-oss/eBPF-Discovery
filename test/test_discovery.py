from utils import discovered_service_has_clients, send_http_requests


def test_service_discovery(run_ebpf_discovery, run_http_service):
    url = run_http_service + "/some/url"
    requests_num = 5
    send_http_requests(url, requests_num)
    assert discovered_service_has_clients(run_ebpf_discovery, url,
                                          local_clients_number=requests_num, external_clients_number=0)

    url = run_http_service + "/other/url"
    requests_num = 10
    send_http_requests(url, requests_num)
    assert discovered_service_has_clients(run_ebpf_discovery, url,
                                          local_clients_number=requests_num, external_clients_number=0)

    # TODO: uncomment when discovery handles X-Forwarded-For properly
    # url = run_http_service + "/forwarded"
    # requests_num = 2
    # send_http_requests(url, requests_num, "1.2.3.4")
    # assert discovered_service_has_clients(run_ebpf_discovery, url,
    #                                       local_clients_number=0, external_clients_number=requests_num)
