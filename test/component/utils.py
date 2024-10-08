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

import json
import logging
import subprocess
import time

import requests
from pyroute2 import IPRoute
from urllib.parse import urlparse


def send_http_requests(url: str, requests_num: int, client_ip_value: str | None = None, client_ip_key: str = "X-Forwarded-For",
                       headers : dict | None = None):
    if headers is None:
        headers = {}
    if client_ip_value:
        headers.update({client_ip_key: client_ip_value})
    for i in range(requests_num):
        requests.get(url, verify=False, headers=headers)

def is_responsive(url: str) -> bool:
    try:
        response = requests.get(url, verify=False)
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
        parsed_url1 = urlparse(url)
        parsed_url2 = urlparse("x://" + endpoint)
        normalized_url1 = (parsed_url1.hostname, parsed_url1.port, parsed_url1.path)
        normalized_url2 = (parsed_url2.hostname, parsed_url2.port, parsed_url2.path)
        return normalized_url1 == normalized_url2

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


def discovered_service_has_expected_clients(discovery: subprocess.Popen, url: str, expected_internal_clients: int,
                                            expected_external_clients: int) -> bool:
    service = get_discovered_service_json(discovery, url)
    if not service:
        logging.warning("No discovered service for endpoint {}".format(url))
        return False
    if service.get("internalClientsNumber", 0) != expected_internal_clients:
            logging.warning("Internal clients number mismatch ({}!={}) for endpoint {}"
                            .format(service.get("internalClientsNumber", "0"), expected_internal_clients, url))
            return False
    if service.get("externalClientsNumber", 0) != expected_external_clients:
            logging.warning("External clients number mismatch ({}!={}) for endpoint {}"
                            .format(service.get("externalClientsNumber", "0"), expected_external_clients, url))
            return False
    return True


def create_network_interface(type, name, ip_address, mask):
    with IPRoute() as ipr:
        try:
            ipr.link('add', ifname=name, kind=type)
            ipr.link('set', index=ipr.link_lookup(ifname=name)[0], state='up')
            ipr.addr('add', index=ipr.link_lookup(ifname=name)[0], address=ip_address, prefixlen=mask)
            logging.info(f"Network interface {name} created")
        except Exception as e:
            logging.error(f"Error deleting network interface {name}: {e}")


def delete_network_interface(name):
    with IPRoute() as ipr:
        try:
            ipr.flush_addr(index=ipr.link_lookup(ifname=name)[0])
            ipr.link('set', index=ipr.link_lookup(ifname=name)[0], state='down')
            ipr.link('del', index=ipr.link_lookup(ifname=name)[0])
            logging.info(f"Bridge {name} deleted")
        except Exception as e:
            logging.error(f"Error deleting network interface {name}: {e}")


