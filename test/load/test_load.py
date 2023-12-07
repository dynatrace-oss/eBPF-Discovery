import gevent
from locust import FastHttpUser, task, constant_throughput
from locust.env import Environment

from utils import generate_random_url, generate_random_ip


class HttpServerRequestUser(FastHttpUser):
    wait_time = constant_throughput(50)

    @task
    def random_request(self) -> None:
        self.client.get(f"/{generate_random_url()}", headers={"X-Forwarded-For": generate_random_ip()})


def test_load(run_ebpf_discovery, run_fast_api_http_service) -> None:
    env = Environment(user_classes=[HttpServerRequestUser], host=run_fast_api_http_service)
    runner = env.create_local_runner()
    env.runner.start(2000, spawn_rate=200)
    gevent.spawn_later(1800, lambda: runner.quit())
    env.runner.greenlet.join()
