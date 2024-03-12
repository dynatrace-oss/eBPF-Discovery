/*
 * Copyright 2023 Dynatrace LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

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
