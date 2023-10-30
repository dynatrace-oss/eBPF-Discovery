# eBPF Discovery

eBPF Discovery is a tool for discovering HTTP endpoints on a given host based on incoming HTTP requests.

## Prerequisites

* conan >= 1.56.0
* cmake >= 3.22.3
* libelf-dev
* clang

## Building
```
cmake -DCMAKE_BUILD_TYPE=<build type> -DCMAKE_C_COMPILER=gcc '-DCMAKE_CXX_COMPILER=g++' -DBUILD_TESTS=ON -DBUILD_BPF_TESTS=ON -DPROJECT_VERSION=<version> -S . -B <build dir>
cmake --build <build dir>
```
`<version>` must be provided in the format major.minor.patch e.g. 1.2.3

## Installation

```
DESTDIR=/ cmake --install <build dir> --prefix /usr/local
```

## Help & Support

eBPF Discovery is an open source project. The features are fully supported by [Dynatrace](https://www.dynatrace.com).

**Get Help**

* Ask a question in the [product forums](https://community.dynatrace.com/t5/Using-Dynatrace/ct-p/UsingDynatrace)

**Open a GitHub issue to:**

* Report minor defects, minor items or typos
* Ask for improvements or changes
* Ask any questions related to the community effort

SLAs don't apply for GitHub tickets

**Customers can open a ticket on the [Dynatrace support portal](https://support.dynatrace.com/supportportal/) to:**

* Get support from the Dynatrace technical support engineering team
* Manage and resolve product related technical issues

SLAs apply according to the customer's support level.

## Contributing

See CONTRIBUTING.md for details on submitting changes.

## License

eBPF Discovery is under Apache 2.0 license. See LICENSE for details.
