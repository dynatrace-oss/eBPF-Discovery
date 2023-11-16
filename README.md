# eBPF Discovery

eBPF Discovery is a tool for discovering HTTP endpoints on a given host based on incoming HTTP requests.
Only Linux kernels of version 5.3.0 or above are supported.

**Output data**

The output data model is defined in [service.proto file](libebpfdiscoveryproto/ebpfdiscoveryproto/service.proto). Incoming HTTP requests are aggregated into services by unique PID and endpoint. Additionaly, services have counters describing how many internal and external clients have connected to them.
Discovered services are popped from the program in a specified time interval, serialized to JSON format and sent to the program's standard output, i.e.:
```
{"service":[{"pid":172613,"endpoint":"127.0.0.1:8000/","internalClientsNumber":1}]}
```

## Building

**Prerequisites**
* conan >= 1.56.0
* cmake >= 3.22.3
* libelf-dev
* clang

**Build**

```
cmake -DCMAKE_BUILD_TYPE=<build type> -DCMAKE_C_COMPILER=gcc '-DCMAKE_CXX_COMPILER=g++' -DBUILD_TESTS=ON -DBUILD_BPF_TESTS=ON -DPROJECT_VERSION=<version> -S . -B <build dir>
cmake --build <build dir>
```
`<version>` must be provided in the format major.minor.patch e.g. 1.2.3

**Installation**

```
DESTDIR=/ cmake --install <build dir> --prefix /usr/local
```

## Usage

To run eBPF Discovery, simply run:
```
./ebpfdiscoverysrv [OPTIONS]
```
The program needs to be run either as superuser or with the following capabilities assigned:
```
cap_dac_override, cap_sys_admin, cap_sys_resource+ep
```
Please note that in order run eBPF Discovery on a system it needs to have eBPF support enabled in the kernel.

**Command line arguments**

Optional command line arguments can be set in place of the OPTIONS tag:

|Option               |Description                                                                                                    |Default value                       |
|---------------------|---------------------------------------------------------------------------------------------------------------|------------------------------------|
|`--help, -h`         |Display available options.                                                                                     |false                               |
|`--interval=VALUE`   |Set the time inteval (in seconds) in which the discovered services are reported to the programs standard output|60 (seconds).                       |
|`--log-dir=DIRECTORY`|Set log files directory.                                                                                       |eBPF Discovery binary root directory|
|`--log-level=LEVEL`  |Set logging level, where LEVEL={trace, debug, info, warning, error, critical, off}.                            |error                               |
|`--log-no-stdout`    |Disable logging to stdout.                                                                                     |false                               |
|`--test-launch`      |Exit program after launch for testing purposes.                                                                |false                               |
|`--version`          |Display program version.                                                                                       |false                               |


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
The BPF code in kernel space is under GPLv2 license.