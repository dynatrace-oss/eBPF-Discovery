# eBPF Discovery

eBPF Discovery is a tool for discovering HTTP endpoints on a given host based on incoming HTTP requests.

## Build requirements

```
conan 2.0
cmake 3.23
libelf-dev
libboost-all-dev
libfmt-dev
clang
```

## Setup

Build release:

```
conan install . --build=missing -s build_type=Release
cmake --preset conan-release -DBUILD_TESTS=OFF
cmake --build --preset conan-release
```

Install release:

```
DESTDIR=/ cmake --install <build dir> --prefix /usr/local
```

Build debug:

```
conan install . --build=missing -s build_type=Debug
cmake --preset conan-debug -DTHIRDPARTY_MAKE_JOBS_COUNT=$((`nproc` / 2)) -DBUILD_BPF_TESTS=On
cmake --build --preset conan-debug
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
