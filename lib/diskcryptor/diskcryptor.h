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

#ifndef _CRYPTSETUP_DISKCRYPTOR_H
#define _CRYPTSETUP_DISKCRYPTOR_H

#define DISKCRYPTOR_HDR_SALT_LEN 64
#define DISKCRYPTOR_HDR_WHOLE_LEN    2048
#define DISKCRYPTOR_HDR_ENC_LEN    (DISKCRYPTOR_HDR_WHOLE_LEN - DISKCRYPTOR_HDR_SALT_LEN)

struct diskcryptor_enchdr {
	char salt[DISKCRYPTOR_HDR_SALT_LEN];
	char encrypted[DISKCRYPTOR_HDR_ENC_LEN];
} __attribute__((__packed__));

#define DISKCRYPTOR_HDR_KEY_LEN 64

struct diskcryptor_phdr {
	char _trash[DISKCRYPTOR_HDR_SALT_LEN];
	char signature[4];
        uint32_t crc32;
        uint16_t header_version;
        uint32_t flags;
        uint32_t uuid;

        uint32_t alg;
        char key[256];
        uint32_t previous_alg;
        char previous_key[256];

        uint64_t relocation_offset;
        uint64_t data_size;
        uint64_t encrypted_size;
        uint8_t wipe_mode;

        char padding[1421];
} __attribute__((__packed__));


struct crypt_device;
struct crypt_params_diskcryptor;

int DISKCRYPTOR_read_phdr(struct crypt_device *cd,
		     struct diskcryptor_phdr *hdr,
		     struct crypt_params_diskcryptor *params);

#endif
