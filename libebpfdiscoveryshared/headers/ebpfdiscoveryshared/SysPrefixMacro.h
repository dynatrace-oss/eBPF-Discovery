/*
 * Copyright 2024 Dynatrace LLC
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

#if defined(__TARGET_ARCH_x86)
#	define SYS_PREFIX "__x64_"
#elif defined(__TARGET_ARCH_s390)
#	define SYS_PREFIX "__s390x_"
#elif defined(__TARGET_ARCH_arm64)
#	define SYS_PREFIX "__arm64_"
#else
#	define SYS_PREFIX "__se_"
#endif
