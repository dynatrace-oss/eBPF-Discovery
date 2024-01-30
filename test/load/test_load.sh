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

discoveryBinPath="$1"
logDirPath="$2"
users="$3"
spawnRate="$4"
runTime="$5"

ebpfDiscoveryProcessRegex="ebpfdiscoverysr*"

(uvicorn http_server:app --host 127.0.0.1 --port 8000 &)

(sudo "${discoveryBinPath}" --interval 2 --log-no-stdout --log-dir "${logDirPath}" --log-level debug &)

locust -f locustfile.py --host http://127.0.0.1:8000 --headless --users "${users}" --spawn-rate "${spawnRate}" --run-time "${runTime}"

if ! pgrep -x "${ebpfDiscoveryProcessRegex}" > /dev/null; then
  echo "eBPF Discovery is not running. Exiting with error."
  exit 1
fi
