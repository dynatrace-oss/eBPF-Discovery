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

FROM ubuntu:18.04

RUN apt-get update -y && \
    # for add-apt-repository
    apt-get install -y software-properties-common && \
    # for version 9.x of gcc/g++
    add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt-get install -y wget lsb-release gpg libelf-dev gcc-9 g++-9 python3-pip git libc6-dev-i386 && \
    # update links to use version 9.x of gcc/g++
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 800 --slave /usr/bin/g++ g++ /usr/bin/g++-9 && \
    # install clang 12
    wget --timeout=10 --tries=3 -O - https://apt.llvm.org/llvm.sh | bash -s - 12 && \
    pip3 install conan==1.56.0 cmake==3.22.3

ENV PATH="/usr/lib/llvm-12/bin:$PATH"
