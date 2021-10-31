/*
 * DiskCryptor-compatible volume handling
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <iconv.h>

#include "libcryptsetup.h"
#include "diskcryptor.h"
#include "internal.h"

// copied from lib/bitlk/bitlk.c
static int passphrase_to_utf16(struct crypt_device *cd, char *input, size_t inlen, char **out)
{
	char *outbuf = NULL;
	iconv_t ic;
	size_t ic_inlen = inlen;
	size_t ic_outlen = inlen * 2;
	char *ic_outbuf = NULL;
	size_t r = 0;

	if (inlen == 0)
		return r;

	outbuf = crypt_safe_alloc(inlen * 2);
	if (outbuf == NULL)
		return -ENOMEM;

	memset(outbuf, 0, inlen * 2);
	ic_outbuf = outbuf;

	ic = iconv_open("UTF-16LE", "UTF-8");
	r = iconv(ic, &input, &ic_inlen, &ic_outbuf, &ic_outlen);
	iconv_close(ic);

	if (r == 0) {
		*out = outbuf;
	} else {
		*out = NULL;
		crypt_safe_free(outbuf);
		log_dbg(cd, "Failed to convert passphrase: %s", strerror(errno));
		r = -errno;
	}

	return r;
}

static void hexdump_buffer(FILE *stream, const unsigned char *buffer,
                size_t buffer_size, const int bytes_per_line)
{
	// TODO: make the function more readable
	// TODO: replace fprintf with something faster, like sprintf
	for (size_t i = 0; i < buffer_size; i+=bytes_per_line) {
		fprintf(stream, "%08x  ", (unsigned int) i);

		for (size_t j = i; j < i + bytes_per_line && j < buffer_size; j++) {
			fprintf(stream, "%02x ", (unsigned int) buffer[j]);
		}
		// last line padding
		for (size_t j = buffer_size; j < i + bytes_per_line; j++) {
			fputs("   ", stream);
		}

		fprintf(stream, " |");
		for (size_t j = i; j < i+bytes_per_line && j < buffer_size; j++) {
			if (isprint(buffer[j])) {
				fputc(buffer[j], stream);
			} else {
				fputc('.', stream);
			}
		}
		// last line padding
		for (size_t j = buffer_size; j < i+bytes_per_line; j++) {
			fputs(" ", stream);
		}
		fprintf(stream, "|\n");
	}
}


static void hexprint(struct crypt_device *cd, const char *d, int n, const char *sep)
{
	int i;
	for(i = 0; i < n; i++)
		log_std(cd, "%02hhx%s", (const char)d[i], sep);
}

/*
 * Checks if the header signature and CRC32 matches, to determine
 * if the password is correct. Does not validate other header fields.
 */
static bool DISKCRYPTOR_is_correctly_decrypted(struct crypt_device *cd,
                struct diskcryptor_phdr *hdr)
{
        if (strncmp(hdr->signature, "DCRP", 4))
                return false;

        // DiskCryptor uses unmodified CRC-32
        uint32_t header_crc = crypt_crc32(0xffffffff,
                        (const unsigned char*)hdr + 72, 2048-72);
        // crypt_crc32() does not perform the final XOR
        header_crc ^= 0xffffffff;

        // TODO: big-endian architectures?
        if (header_crc != hdr->crc32)
                return false;

        return true;
}

int DISKCRYPTOR_decrypt_hdr(struct crypt_device *cd,
			   struct diskcryptor_enchdr *enchdr,
			   struct diskcryptor_phdr *hdr,
			   struct crypt_params_diskcryptor *params)
{
	char *key;
        int r;
	struct crypt_cipher *cipher;
	char iv[16] = {};

	assert(sizeof(struct diskcryptor_enchdr) == DISKCRYPTOR_HDR_WHOLE_LEN);
	assert(sizeof(struct diskcryptor_phdr) == DISKCRYPTOR_HDR_WHOLE_LEN);

        if (posix_memalign((void*)&key, crypt_getpagesize(), DISKCRYPTOR_HDR_MAX_KEY_LEN))
                return -ENOMEM;

        char *utf16Password = NULL;
        r = passphrase_to_utf16(cd, CONST_CAST(char *) params->passphrase, params->passphrase_size, &utf16Password);

        r = crypt_pbkdf("pbkdf2", "sha512",
                        utf16Password, params->passphrase_size * 2,
                        enchdr->salt, DISKCRYPTOR_HDR_SALT_LEN,
                        key, DISKCRYPTOR_HDR_KEY_LEN * 2,
                        1000, 0, 0);

        // TODO: czy na pewno xts-plain64, czy też raczej xts-plain
        r = crypt_cipher_init(&cipher, "twofish", "xts", key+64, 64);
        if (!r) {
                // TODO: co w wypadku sektorów 4k / większych niż 512 bajtów?
                for (int i = 0; i < DISKCRYPTOR_HDR_WHOLE_LEN / 512; i++) {
                        iv[0] = i+1;
                        r = crypt_cipher_decrypt(cipher,
                                (const char *)enchdr + i * 512,
                                (char *)hdr + i * 512,
                                512,
                                iv, 16);

                        // TODO: sprawdzać wartość r,
                }
                crypt_cipher_destroy(cipher);
        }

        memcpy(enchdr, hdr, DISKCRYPTOR_HDR_WHOLE_LEN);

        // TODO: czy na pewno xts-plain64, czy też raczej xts-plain
        r = crypt_cipher_init(&cipher, "aes", "xts", key, 64);
        if (!r) {
                // TODO: co w wypadku sektorów 4k / większych niż 512 bajtów?
                for (int i = 0; i < DISKCRYPTOR_HDR_WHOLE_LEN / 512; i++) {
                        iv[0] = i+1;
                        r = crypt_cipher_decrypt(cipher,
                                (const char *)enchdr + i * 512,
                                (char *)hdr + i * 512,
                                512,
                                iv, 16);

                        // TODO: sprawdzać wartość r,
                }
                crypt_cipher_destroy(cipher);
        }

        if (DISKCRYPTOR_is_correctly_decrypted(cd, hdr)) {
                log_std(cd, "DONE\n");
                // hexprint(cd, hdr, 2048, " ");

                hexdump_buffer(stderr, hdr, 2048, 16);

                return 0;
        }
        // TODO: little-endian vs big-endian

	if (key)
		crypt_safe_memzero(key, DISKCRYPTOR_HDR_MAX_KEY_LEN);



        return r;
}

int DISKCRYPTOR_decrypt_sector(struct crypt_device *cd,
                struct diskcryptor_phdr *hdr,
                uint64_t sector_number)
{
        int r;
	struct crypt_cipher *cipher;
	char iv[16] = {};
        char *sector = malloc(512);
        char *sector_decrypted = malloc(512);

	struct device *device = crypt_data_device(cd);
        int devfd;
        devfd = device_open(cd, device, O_RDONLY);
	if (devfd < 0) {
		device_free(cd, device);
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

	if (!read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), sector, DISKCRYPTOR_HDR_WHOLE_LEN, sector_number * 512)
                        == 512) {

		device_free(cd, device);
		log_err(cd, _("Cannot read device %s."), device_path(device));
		return -EINVAL;
        }

        r = crypt_cipher_init(&cipher, "aes", "xts", hdr->key, 64);

        for (int i = 16300; i <= 16400; i++) {
                iv[0] = i % 256;
                iv[1] = i / 256;

                fprintf(stderr, "\n\ni=%d\n", i);

                r = crypt_cipher_decrypt(cipher,
                        sector,
                        sector_decrypted,
                        512,
                        iv, 16);

                hexdump_buffer(stderr, sector_decrypted, 512, 16);
        }

        free(sector);
        free(sector_decrypted);

        return 0;
}

int DISKCRYPTOR_read_phdr(struct crypt_device *cd,
		     struct diskcryptor_phdr *hdr,
		     struct crypt_params_diskcryptor *params)
{
        int r = 0;
        int devfd;
	struct device *device = crypt_data_device(cd);
        struct diskcryptor_enchdr *enchdr;

        devfd = device_open(cd, device, O_RDONLY);
	if (devfd < 0) {
		device_free(cd, device);
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

        enchdr = malloc(sizeof(struct diskcryptor_enchdr));
        // TODO: if (enchdr == NULL)

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), enchdr, DISKCRYPTOR_HDR_WHOLE_LEN, 0) == DISKCRYPTOR_HDR_WHOLE_LEN) {
		r = DISKCRYPTOR_decrypt_hdr(cd, enchdr, hdr, params);

                //DISKCRYPTOR_decrypt_sector(cd, hdr, 16380);
        }

	if (r < 0)
		memset(hdr, 0, sizeof (*hdr));

        free(enchdr);
	return r;
}
