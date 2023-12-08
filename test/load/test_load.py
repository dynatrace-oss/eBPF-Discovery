import random

from locust import FastHttpUser, task, constant_throughput
from locust.env import Environment
import gevent


class HttpServerRequestUser(FastHttpUser):
    wait_time = constant_throughput(200)

    @task
    def random_request(self) -> None:
        endpoints = ["dummy1", "dummy2", "dummy3", "dummy4", "dummy5"]
        ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        self.client.get(f"/{random.choice(endpoints)}", headers={"X-Forwarded-For": ip})


def test_load(run_ebpf_discovery, run_fast_api_http_service, load_tests_execution_time) -> None:
    env = Environment(user_classes=[HttpServerRequestUser], host=run_fast_api_http_service)
    runner = env.create_local_runner()
    env.runner.start(5, spawn_rate=5)
    gevent.spawn_later(load_tests_execution_time, lambda: runner.quit())
    env.runner.greenlet.join()
