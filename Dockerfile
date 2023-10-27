FROM ubuntu:18.04

ARG KERNEL_VERSION=4.15.0-101-generic
ENV KERNEL_VERSION=$KERNEL_VERSION
RUN apt update -y && \
	apt install -y \
	# for the new clang
	wget lsb-release gpg software-properties-common \
	# for preparing dependencies
	git libelf-dev libboost-program-options-dev \
	make gcc-8 g++-8 linux-headers-$KERNEL_VERSION cmake && \
	# update links to use version 8.x of gcc/g++
	update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 800 --slave /usr/bin/g++ g++ /usr/bin/g++-8 && \
	update-alternatives --install /usr/bin/cc cc /usr/bin/gcc 100 --slave /usr/bin/c++ c++ /usr/bin/g++
RUN wget --timeout=10 --tries=3 -O - https://apt.llvm.org/llvm.sh | bash -s - 10
