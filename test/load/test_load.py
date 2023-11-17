import time
from typing import Optional, Tuple

from locust import FastHttpUser, LoadTestShape, task, between
from locust.env import Environment

from utils import generate_random_url, generate_random_ip


class StepLoadShape(LoadTestShape):
    def tick(self) -> Optional[Tuple[int, int]]:
        users = 2000
        spawn_rate = 200
        return users, spawn_rate


class HttpServerRequestUser(FastHttpUser):
    wait_time = between(0.5, 2)

    @task
    def random_request(self) -> None:
        self.client.get(f"/{generate_random_url()}", headers={"X-Forwarded-For": generate_random_ip()})


def test_load(run_ebpf_discovery, run_fast_api_http_service) -> None:
    env = Environment(user_classes=[HttpServerRequestUser], shape_class=StepLoadShape(), host=run_fast_api_http_service)
    env.create_local_runner()
    env.runner.start_shape()
    time.sleep(1800)
    env.runner.quit()
