import json
import logging
import requests
import subprocess
import typing


def send_http_requests(url: str, requests_num: int, x_forwarded_for: typing.Optional[str] = None):
    headers = {}
    if x_forwarded_for:
        headers.update({"X-Forwarded-For": x_forwarded_for})
    for i in range(requests_num):
        requests.get(url, headers=headers)


def get_discovered_service_json(discovery: subprocess.Popen, url: str) -> typing.Optional[dict]:
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
