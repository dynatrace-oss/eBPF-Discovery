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


def discovered_service_has_clients(discovery: subprocess.Popen, url: str, internal_clients_number: int,
                                   external_clients_number: int) -> bool:
    service = get_discovered_service_json(discovery, url)
    if not service:
        logging.warning("No discovered service for endpoint {}".format(url))
        return False
    if internal_clients_number:
        if service.get("internalClientsNumber", 0) != internal_clients_number:
            logging.warning("Internal clients number mismatch ({}!={}) for endpoint {}"
                            .format(service.get("internalClientsNumber", "0"), internal_clients_number, url))
            return False
    if external_clients_number:
        if service.get("externalClientsNumber", 0) != external_clients_number:
            logging.warning("External clients number mismatch ({}!={}) for endpoint {}"
                            .format(service.get("externalClientsNumber", "0"), external_clients_number, url))
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


