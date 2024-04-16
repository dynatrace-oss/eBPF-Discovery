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

import glob
import logging
import os
import subprocess
import sys
from time import sleep

import pytest

from utils import is_responsive, wait_until, create_network_interface, delete_network_interface

@pytest.fixture(autouse=True)
def print_newline(request):
    print() # https://github.com/pytest-dev/pytest/issues/8574
    yield

def pytest_configure(config):
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S'
                        )


def pytest_addoption(parser):
    parser.addoption("--discovery_path", action="store", help="Path to eBPF Discovery binary")
    parser.addoption("--log_dir", action="store", help="Path to log directory")
    parser.addoption("--http_server_port", action="store", help="Port on which to run http server", default=9000)
    parser.addoption("--load-tests-execution-time", action="store", help="Load tests execution time in seconds", default=1800)


@pytest.fixture(scope="function")
def discovery_path(pytestconfig):
    discovery_path = pytestconfig.getoption("discovery_path")
    assert discovery_path, "Path to eBPF discovery needs to be provided via --discovery_path"
    return discovery_path


@pytest.fixture(scope="function")
def log_dir(pytestconfig):
    log_dir = pytestconfig.getoption("log_dir")
    assert log_dir, "Path tolog directory needs to be provided via --log_dir"
    return log_dir


@pytest.fixture(scope="function")
def http_server_port(pytestconfig):
    port = pytestconfig.getoption("http_server_port")
    return port


@pytest.fixture
def load_tests_execution_time(pytestconfig):
    load_tests_execution_time = pytestconfig.getoption("--load-tests-execution-time")
    return int(load_tests_execution_time)


@pytest.fixture(scope='function')
def network_interfaces(request):
    for interface in request.param:
        type, name, ip_address, mask = interface
        create_network_interface(type, name, ip_address, mask)
    yield request.param
    for interface in request.param:
        type, name, ip_address, mask = interface
        delete_network_interface(name)


@pytest.fixture(scope="function")
def run_ebpf_discovery(discovery_path, log_dir):
    args = (discovery_path, "--interval", "2", "--log-no-stdout", "--log-dir", log_dir,
            "--log-level", "debug")
    discovery = subprocess.Popen(args, stdout=subprocess.PIPE)
    sleep(0.2)  # delay to avoid sending requests before ebpf_discovery is responsive
    yield discovery

    discovery.terminate()
    while discovery.poll() is None:
        sleep(0.2)

    log_files = glob.glob(log_dir + f'/*{discovery.pid}.log')
    assert log_files != [], "eBPF Discovery didn't produce any log files"

    print() # https://github.com/pytest-dev/pytest/issues/8574
    logging.info("eBPF Discovery produced logs:")
    for file in log_files:
        with open(file, 'r') as f:
            content = f.read()
            logging.info("{} content:\n{}".format(file, content.strip()))

    exit_code = discovery.returncode
    assert not exit_code, "eBPF Discovery returned exit code: {}".format(exit_code)


@pytest.fixture(scope="function")
def run_http_service(http_server_port):
    ip_addr = "127.0.0.1"
    url = "http://{}:{}".format(ip_addr, http_server_port)
    args = (sys.executable, "-m", "http.server", "--bind", ip_addr, str(http_server_port))
    server = subprocess.Popen(args)
    wait_until(lambda: is_responsive(url), timeout=10)
    yield url
    server.terminate()


@pytest.fixture(scope="function")
def run_fast_api_http_service(http_server_port):
    ip_addr = "127.0.0.1"
    url = "http://{}:{}".format(ip_addr, http_server_port)
    workers = "12"
    args = (sys.executable, "-m", "uvicorn", "fast_api_server:app", "--host", ip_addr, "--port", str(http_server_port), "--workers", workers)
    server = subprocess.Popen(args, cwd=os.environ.get("TESTING_PATH"))
    wait_until(lambda: is_responsive(url), timeout=10)
    yield url
    server.terminate()
