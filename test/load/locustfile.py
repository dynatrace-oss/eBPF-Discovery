import random

from locust import FastHttpUser, task, constant_throughput


class HttpServerRequestUser(FastHttpUser):
    wait_time = constant_throughput(200)

    @task
    def random_request(self) -> None:
        endpoints = ["dummy1", "dummy2", "dummy3", "dummy4", "dummy5"]
        ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        self.client.get(f"/{random.choice(endpoints)}", headers={"X-Forwarded-For": ip})
