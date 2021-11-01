/*
 * DiskCryptor-compatible header definition
 *
 * Copyright (C) 2021 Mateusz Jończyk
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _CRYPTSETUP_DCRYPTOR_H
#define _CRYPTSETUP_DCRYPTOR_H

#define DCRYPTOR_HDR_LEN    2048
#define DCRYPTOR_SALT_LEN 64

struct dcryptor_enchdr {
	char salt[DCRYPTOR_SALT_LEN];
	char encrypted[DCRYPTOR_HDR_LEN - DCRYPTOR_SALT_LEN];
} __attribute__((__packed__));

#define DCRYPTOR_KEY_LEN 64
// Header provides space for separate keys for 4 chained ciphers
#define DCRYPTOR_MAX_KEYS 4
#define DCRYPTOR_MAX_CHAINED_KEYS_LEN DCRYPTOR_HDR_KEY_LEN * DCRYPTOR_MAX_KEYS

struct dcryptor_phdr {
	char _trash[DCRYPTOR_SALT_LEN];
	char signature[4];
	uint32_t crc32;
	uint16_t header_version;
	uint32_t flags;
	uint32_t uuid;

	uint32_t alg_id;
	char key[DCRYPTOR_MAX_KEYS][DCRYPTOR_KEY_LEN];
	uint32_t previous_alg_id;
	char previous_key[DCRYPTOR_MAX_KEYS][DCRYPTOR_KEY_LEN];

	uint64_t relocation_offset;
	uint64_t data_size;
	uint64_t encrypted_size;
	uint8_t wipe_mode;

	char padding[1421];
} __attribute__((__packed__));


struct crypt_device;
struct crypt_params_dcryptor;

int DCRYPTOR_read_phdr(struct crypt_device *cd,
		     struct dcryptor_phdr *hdr,
		     struct crypt_params_dcryptor *params);

int DCRYPTOR_activate(struct crypt_device *cd,
		     const char *name,
		     struct dcryptor_phdr *hdr,
		     struct crypt_params_dcryptor *params,
		     uint32_t flags);

#endif
