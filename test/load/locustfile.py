# Copyright 2024 Dynatrace LLC
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

import random

from locust import FastHttpUser, task, constant_throughput


class HttpServerRequestUser(FastHttpUser):
    wait_time = constant_throughput(200)

    @task
    def random_request(self) -> None:
        endpoints = ["dummy1", "dummy2", "dummy3", "dummy4", "dummy5"]
        ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        self.client.get(f"/{random.choice(endpoints)}", headers={"X-Forwarded-For": ip})
