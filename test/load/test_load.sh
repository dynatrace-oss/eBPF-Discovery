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
