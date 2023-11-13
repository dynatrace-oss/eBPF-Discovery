FROM ubuntu:18.04

RUN apt-get update -y && \
    # for add-apt-repository
    apt-get install -y software-properties-common && \
    # for version 9.x of gcc/g++
    add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt-get install -y wget lsb-release gpg libelf-dev gcc-9 g++-9 python3-pip git && \
    # update links to use version 9.x of gcc/g++
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 800 --slave /usr/bin/g++ g++ /usr/bin/g++-9 && \
    # install clang 12
    wget --timeout=10 --tries=3 -O - https://apt.llvm.org/llvm.sh | bash -s - 12 && \
    pip3 install conan==1.56.0 cmake==3.22.3

ENV PATH="/usr/lib/llvm-12/bin:$PATH"
