import json
import logging
import requests
import subprocess
import typing


def send_http_requests(url: str, requests_num: int):
    for i in range(requests_num):
        requests.get(url)


def is_responsive(url: str) -> bool:
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
    except (requests.ConnectionError, requests.ConnectTimeout, requests.Timeout):
        return False


def get_discovered_service_json(discovery: subprocess.Popen, url: str) -> typing.Optional[dict]:
    def url_matches_endpoint(url, endpoint):
        return url[len("http://"):] == endpoint

    output = discovery.stdout.readline()
    if not output:
        return None
    services_json = json.loads(output)
    try:
        for service in services_json["service"]:
            if url_matches_endpoint(url, service["endpoint"]):
                return service
    except KeyError:
        return None
    return None


def discovered_service_has_clients(discovery: subprocess.Popen, url: str, local_clients_number: int, external_clients_number: int) -> bool:
    # HACK remove when discovery starts correctly identifying local and external clients num
    local_clients_number, external_clients_number = external_clients_number, local_clients_number
    # HACK

    service = get_discovered_service_json(discovery, url)
    if not service:
        logging.warning("No discovered service for endpoint {}".format(url))
        return False
    if local_clients_number:
        if service.get("internalClientsNumber", 0) != local_clients_number:
            logging.warning("Internal clients number mismatch ({}!={}) for endpoint {}"
                            .format(service.get("internalClientsNumber", "0"), local_clients_number, url))
            return False
    if external_clients_number:
        if service.get("externalClientsNumber", 0) != external_clients_number:
            logging.warning("External clients number mismatch ({}!={}) for endpoint {}"
                            .format(service.get("externalClientsNumber", "0"), external_clients_number, url))
            return False
    return True
