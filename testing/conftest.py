import os
import pytest
import subprocess
import glob

from utils import discovered_service_has_clients, is_responsive
from time import sleep


def pytest_addoption(parser):
    parser.addoption("--discovery_path", action="store", help="Path to eBPF Discovery binary")


@pytest.fixture(scope="session")
def discovery_path(pytestconfig):
    discovery_path = pytestconfig.getoption("discovery_path")
    assert discovery_path, "Path to eBPF discovery needs to be provided via --discovery_path"
    return discovery_path


@pytest.fixture(scope="session")
def run_ebpf_discovery(discovery_path):
    args = (discovery_path, "--interval", "2")
    discovery = subprocess.Popen(args, stdout=subprocess.PIPE)
    yield discovery

    discovery.terminate()
    while discovery.poll() is None:
        sleep(0.5)
    exit_code = discovery.returncode
    assert not exit_code, "Discovery returned exit code: {}".format(exit_code)

    discovery_root_dir = os.path.dirname(os.path.realpath(discovery_path))
    log_files = glob.glob(discovery_root_dir+'/*.log')
    assert log_files == [], "Discovery produced log files on exit: {}".format(log_files)


@pytest.fixture(scope="session")
def http_service(docker_ip, docker_services, run_ebpf_discovery):
    port = docker_services.port_for("httpbin", 80)
    url = "http://{}:{}/".format(docker_ip, port)
    docker_services.wait_until_responsive(
        timeout=30.0, pause=0.1, check=lambda: is_responsive(url)
    )
    assert discovered_service_has_clients(run_ebpf_discovery, url, 1, 0)
    return url
