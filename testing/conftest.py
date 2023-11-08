import logging
import os
import sys
import pytest
import subprocess
import glob

from time import sleep

logging.basicConfig(level=logging.INFO)


def pytest_addoption(parser):
    parser.addoption("--discovery_path", action="store", help="Path to eBPF Discovery binary")
    parser.addoption("--http_server_port", action="store", help="Port on which to run http server", default=9000)


@pytest.fixture(scope="session")
def discovery_path(pytestconfig):
    discovery_path = pytestconfig.getoption("discovery_path")
    assert discovery_path, "Path to eBPF discovery needs to be provided via --discovery_path"
    return discovery_path


@pytest.fixture(scope="session")
def http_server_port(pytestconfig):
    port = pytestconfig.getoption("http_server_port")
    return port


@pytest.fixture(scope="session")
def run_ebpf_discovery(discovery_path):
    discovery_root_dir = os.path.dirname(os.path.realpath(discovery_path))
    args = (discovery_path, "--interval", "2", "--log-no-stdout", "--log-dir", discovery_root_dir,
            "--log-level", "debug")
    discovery = subprocess.Popen(args, stdout=subprocess.PIPE)
    yield discovery

    discovery.terminate()
    while discovery.poll() is None:
        sleep(0.5)
    exit_code = discovery.returncode
    assert not exit_code, "Discovery returned exit code: {}".format(exit_code)

    log_files = glob.glob(discovery_root_dir+'/*.log')
    assert log_files != [], "Discovery didn't produce any log files"

    logging.info("Discovery produced logs:")
    for file in log_files:
        with open(file, 'r') as f:
            content = f.read()
            logging.info("File: {}\nContent:\n{}".format(file, content))


@pytest.fixture(scope="session")
def run_http_service(http_server_port):
    args = (str(sys.executable), "-m", "http.server", "--bind", "127.0.0.1", str(http_server_port))
    server = subprocess.Popen(args)
    sleep(2)
    yield server
    server.terminate()
