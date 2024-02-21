// SPDX-License-Identifier: GPL-2.0
#pragma once

#include "DebugPrint.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

enum LibSSLKind {
	LIBSSL_KIND_OPENSSL_1_0_2,
	LIBSSL_KIND_OPENSSL_1_1_0,
	LIBSSL_KIND_OPENSSL_1_1_1,
	LIBSSL_KIND_OPENSSL_3_0,
};

#define OPENSSL_SSL_RBIO_OFFSET 8
#define OPENSSL_1_0_2_SSL_BIO_NUM_OFFSET 0x38
#define OPENSSL_1_1_0_SSL_BIO_NUM_OFFSET 0x38
#define OPENSSL_1_1_1_SSL_BIO_NUM_OFFSET 0x30
#define OPENSSL_3_0_SSL_BIO_NUM_OFFSET 0x38

struct LibSSLReadArgs {
	void* ssl;
	char* buf;
};

int getSslRbioOffset(enum LibSSLKind kind) {
	switch (kind) {
	case LIBSSL_KIND_OPENSSL_1_0_2:
		return OPENSSL_SSL_RBIO_OFFSET;
	case LIBSSL_KIND_OPENSSL_1_1_0:
		return OPENSSL_SSL_RBIO_OFFSET;
	case LIBSSL_KIND_OPENSSL_1_1_1:
		return OPENSSL_SSL_RBIO_OFFSET;
	case LIBSSL_KIND_OPENSSL_3_0:
		return OPENSSL_SSL_RBIO_OFFSET;
	default:
		return 0;
	}
}

int getSslBioNumOffset(enum LibSSLKind kind) {
	switch (kind) {
	case LIBSSL_KIND_OPENSSL_1_0_2:
		return OPENSSL_1_0_2_SSL_BIO_NUM_OFFSET;
	case LIBSSL_KIND_OPENSSL_1_1_0:
		return OPENSSL_1_1_0_SSL_BIO_NUM_OFFSET;
	case LIBSSL_KIND_OPENSSL_1_1_1:
		return OPENSSL_1_1_1_SSL_BIO_NUM_OFFSET;
	case LIBSSL_KIND_OPENSSL_3_0:
		return OPENSSL_3_0_SSL_BIO_NUM_OFFSET;
	default:
		return 0;
	}
}

int getFdFromSslKind(void* ssl, enum LibSSLKind kind) {
	__u64 rbioAddr = 0;
	int ret = bpf_probe_read_user(&rbioAddr, sizeof(rbioAddr), (__u64*)((char*)ssl + getSslRbioOffset(kind)));
	if (ret < 0) {
		return ret;
	}

	int fd = 0;
	ret = bpf_probe_read_user(&fd, sizeof(fd), (__u64*)(rbioAddr + getSslBioNumOffset(kind)));
	if (ret < 0) {
		return ret;
	}

	return fd;
}
