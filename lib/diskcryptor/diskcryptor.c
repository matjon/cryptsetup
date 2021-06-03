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

int DISKCRYPTOR_decrypt_hdr(struct crypt_device *cd,
			   struct diskcryptor_enchdr *enchdr,
			   struct diskcryptor_phdr *hdr,
			   struct crypt_params_diskcryptor *params)
{
	char *key;
        int r;
	struct crypt_cipher *cipher;
	char iv[16] = {1};

	assert(sizeof(struct diskcryptor_enchdr) == DISKCRYPTOR_HDR_WHOLE_LEN);
	assert(sizeof(struct diskcryptor_phdr) == DISKCRYPTOR_HDR_WHOLE_LEN);

        if (posix_memalign((void*)&key, crypt_getpagesize(), 512))
                return -ENOMEM;

        char *utf16Password = NULL;
        r = passphrase_to_utf16(cd, CONST_CAST(char *) params->passphrase, params->passphrase_size, &utf16Password);

        r = crypt_pbkdf("pbkdf2", "sha512",
                        utf16Password, params->passphrase_size * 2,
                        enchdr->salt, DISKCRYPTOR_HDR_SALT_LEN,
                        key, DISKCRYPTOR_HDR_KEY_LEN,
                        1000, 0, 0);

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

        if (!strncmp(hdr->signature, "DCRP", 4)) {
                log_std(cd, "DONE\n");
                // hexprint(cd, hdr, 2048, " ");

                hexdump_buffer(stderr, hdr, 2048, 16);
                return 0;
        }
        // TODO: little-endian vs big-endian

        return r;
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
        }

	if (r < 0)
		memset(hdr, 0, sizeof (*hdr));

        free(enchdr);
	return r;
}
