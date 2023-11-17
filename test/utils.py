import json
import logging
import subprocess
import time
import random

import requests


def send_http_requests(url: str, requests_num: int, x_forwarded_for: str | None = None):
    headers = {}
    if x_forwarded_for:
        headers.update({"X-Forwarded-For": x_forwarded_for})
    for i in range(requests_num):
        requests.get(url, headers=headers)


def is_responsive(url: str) -> bool:
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
    except (requests.ConnectionError, requests.ConnectTimeout, requests.Timeout):
        return False


def wait_until(predicate, timeout, period=1):
    while timeout > 0:
        if predicate():
            return True
        time.sleep(period)
        timeout -= period
    return False


def get_discovered_service_json(discovery: subprocess.Popen, url: str) -> dict | None:
    def url_matches_endpoint(url, endpoint):
        return url[len("http://"):] == endpoint

    output = discovery.stdout.readline()
    if not output:
        return None
    try:
        services_json = json.loads(output)
        for service in services_json["service"]:
            if url_matches_endpoint(url, service["endpoint"]):
                return service
    except (json.decoder.JSONDecodeError, KeyError):
        return None
    return None


def discovered_service_has_clients(discovery: subprocess.Popen, url: str, local_clients_number: int,
                                   external_clients_number: int) -> bool:
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

def generate_random_url() -> str:
    def generate_random_string(length) -> str:
        letters = "abcdef"
        result_str = "".join(random.choice(letters) for _ in range(length))
        return result_str

    url_len = random.randint(2, 5)
    url_name = generate_random_string(url_len)
    return url_name


def generate_random_ip() -> str:
    return ".".join(str(random.randint(0, 255)) for _ in range(4))
