#!/bin/bash

binary_path="${1}"
approved_binary_dependencies=("libelf|libz|libm|libdl|librt|libpthread|libc|ld-linux")

depenencies="$(objdump -p "${binary_path}" 2>/dev/null | grep NEEDED | grep -Ev "${approved_binary_dependencies}")"

if [ -n "${depenencies}" ]; then
  echo "Additional dependencies: ${depenencies}"
  exit 1
fi
