// SPDX-License-Identifier: GPL-2.0
#pragma once

#if defined(__TARGET_ARCH_x86)
#	define SYS_PREFIX "__x64_"
#elif defined(__TARGET_ARCH_s390)
#	define SYS_PREFIX "__s390x_"
#elif defined(__TARGET_ARCH_arm64)
#	define SYS_PREFIX "__arm64_"
#else
#	define SYS_PREFIX "__se_"
#endif
