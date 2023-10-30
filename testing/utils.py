import time
import json
import logging

import requests as requests
from requests.exceptions import ConnectionError


def wait_until(predicate, timeout=2, period=0.25):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(period)
    return False


def send_http_requests(url, requests_num):
    for i in range(requests_num):
        requests.get(url)


def is_responsive(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
    except ConnectionError:
        return False


def get_discovered_service_json(discovery, url):
    def url_matches_endpoint(url, endpoint):
        return url[len("http://"):] == endpoint

    output = discovery.stdout.readline()
    if not output:
        return None
    services_json = json.loads(output)
    for service in services_json["service"]:
        if url_matches_endpoint(url, service["endpoint"]):
            return service
    return None


def discovered_service_has_clients(discovery, url, local_clients_number, external_clients_number):
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
