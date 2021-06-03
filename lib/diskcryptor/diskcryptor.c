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


static void hexprint(struct crypt_device *cd, const char *d, int n, const char *sep)
{
	int i;
	for(i = 0; i < n; i++)
		log_std(cd, "%02hhx%s", (const char)d[i], sep);
}

int DISKCRYPTOR_init_hdr(struct crypt_device *cd,
			   struct diskcryptor_phdr *hdr,
			   struct crypt_params_diskcryptor *params)
{
	char *key;
        int r;
	struct crypt_cipher *cipher;
        char buf[512] = {};
	char iv[16] = {1};

        if (posix_memalign((void*)&key, crypt_getpagesize(), 512))
                return -ENOMEM;

        char *utf16Password = NULL;
        r = passphrase_to_utf16(cd, params->passphrase, params->passphrase_size, &utf16Password);

        r = crypt_pbkdf("pbkdf2", "sha512",
                        utf16Password, params->passphrase_size * 2,
                        hdr->salt, DISKCRYPTOR_HDR_SALT_LEN,
                        key, DISKCRYPTOR_HDR_KEY_LEN,
                        1000, 0, 0);

        char new_key[64];
        memcpy(new_key, &key[32], 32);
        memcpy(&new_key[32], key, 32);

        // TODO: czy na pewno xts-plain64, czy też raczej xts-plain
        r = crypt_cipher_init(&cipher, "aes", "xts", key, 64);
        //log_std(cd, "r=%d\n", r);

        // Initial vector uses plain 64bit sector number starting with 0 (in Linux dmcrypt notation it is "plain64" IV).
        if (!r) {
                r = crypt_cipher_decrypt(cipher, hdr, hdr, 2048,
                                        iv, 16);
                //hexprint(cd, hdr->e, 16, " ");
                crypt_cipher_destroy(cipher);
        }
        //log_std(cd, "r=%d\n", r);

        if (!strncmp(hdr->e, "DCRP", 4)) {
                log_std(cd, "DONE\n");
                return 0;
        }

        return r;
}

int DISKCRYPTOR_read_phdr(struct crypt_device *cd,
		     struct diskcryptor_phdr *hdr,
		     struct crypt_params_diskcryptor *params)
{
        int r = 0;
        int devfd;
	struct device *device = crypt_data_device(cd);


        devfd = device_open(cd, device, O_RDONLY);
	if (devfd < 0) {
		device_free(cd, device);
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), hdr, DISKCRYPTOR_HDR_WHOLE_LEN, 0) == DISKCRYPTOR_HDR_WHOLE_LEN) {
		r = DISKCRYPTOR_init_hdr(cd, hdr, params);
        }

	if (r < 0)
		memset(hdr, 0, sizeof (*hdr));
	return r;
}
