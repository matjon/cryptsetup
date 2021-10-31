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
#include "dcryptor.h"
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


// These structures and list heavily by a similar list in tcrypt/tcrypt.c
struct dcryptor_alg {
		const char *name;
		unsigned int key_offset;
		unsigned int iv_offset;
};

struct dcryptor_algs {
        uint32_t alg_id;       // as used in the volume header
	unsigned int chain_length;
	const char *long_name;
	struct dcryptor_alg cipher[3];
};

static struct dcryptor_algs dcryptor_cipher[] = {
        { 0x0, 1, "aes",
                {{"aes",      0, 32}}},
        { 0x1, 1, "twofish",
                {{"twofish",  0, 32}}},
        { 0x2, 1, "serpent",
                {{"serpent",  0, 32}}},
        { 0x3, 2, "aes-twofish",
                {{"aes",     32, 32*3},
                {"twofish",   0, 32*2}}},
        { 0x4, 2, "twofish-serpent",
                {{"twofish", 32, 32*3},
                {"serpent",   0, 32*2}}},
        { 0x5, 2, "serpent-aes",
                {{"serpent", 32, 32*3},
                {"aes",       0, 32*2}}},
        { 0x6, 3, "aes-twofish-serpent", {
                {"aes",    32*2, 32*5},
                {"twofish",  32, 32*4},
                {"serpent",   0, 32*3},
                }},
        {}
};

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
static bool DCRYPTOR_is_correctly_decrypted(struct dcryptor_phdr *hdr)
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


int DCRYPTOR_decrypt_hdr_one_cipher(char *key,
                struct dcryptor_enchdr *dest,
                struct dcryptor_enchdr *source,
                struct dcryptor_alg *alg)
{
	struct crypt_cipher *cipher;
        char *key_one;
        int r;
	char iv[16] = {};

        if (posix_memalign((void*)&key_one, crypt_getpagesize(), DCRYPTOR_HDR_KEY_LEN))
                return -ENOMEM;

        memcpy(key_one, key + alg->key_offset, 32);
        memcpy(key_one+32, key + alg->iv_offset, 32);

        // TODO: czy na pewno xts-plain64, czy też raczej xts-plain
        r = crypt_cipher_init(&cipher, alg->name, "xts", key_one, 64);
        if (r)
                goto exit;

        // TODO: co w wypadku sektorów 4k / większych niż 512 bajtów?
        for (int i = 0; i < DCRYPTOR_HDR_LEN / 512; i++) {
                iv[0] = i+1;
                r = crypt_cipher_decrypt(cipher,
                        (const char *)source + i * 512,
                        (char *)dest + i * 512,
                        512,
                        iv, 16);

        }
        crypt_cipher_destroy(cipher);

exit:
	if (key_one)
		crypt_safe_memzero(key_one, DCRYPTOR_HDR_KEY_LEN);

        free(key_one);
        return r;
}

int DCRYPTOR_decrypt_hdr_one_combination(char *key,
                struct dcryptor_enchdr *enchdr,
                struct dcryptor_phdr *hdr,
                struct dcryptor_algs *algs)
{
        int i;
        int r;
        struct dcryptor_enchdr *temp_hdr;

        if (posix_memalign((void*)&temp_hdr, crypt_getpagesize(),
                                DCRYPTOR_HDR_LEN)) {
                return -ENOMEM;
        }

        memcpy(temp_hdr, enchdr, DCRYPTOR_HDR_LEN);

        for (i = 0; i < algs->chain_length; i++) {
                r = DCRYPTOR_decrypt_hdr_one_cipher(key,
                                (struct dcryptor_enchdr *) hdr,
                                temp_hdr, &algs->cipher[i]);
                if (r)
                        goto exit;

                memcpy(temp_hdr, hdr, DCRYPTOR_HDR_LEN);
        }

        if (DCRYPTOR_is_correctly_decrypted(hdr))
                r = 0;
        else
                r = 1;

exit:

	if (temp_hdr)
		crypt_safe_memzero(temp_hdr, DCRYPTOR_HDR_LEN);

        free(temp_hdr);
        return r;
}


// Try all combinations that have a specific chain_length, calculating pbkdf2
// once
int DCRYPTOR_decrypt_hdr_one_chain_length(
                struct crypt_device *cd,
                struct dcryptor_enchdr *enchdr,
                struct dcryptor_phdr *hdr,
                char *pwd_utf16,
                int pwd_utf16_length,
                int chain_length,
                int *found_combination)
{
	char *key;
        int r;
        int ret = 1;
        int i;

        if (posix_memalign((void*)&key, crypt_getpagesize(), DCRYPTOR_HDR_KEY_LEN * chain_length))
                return -ENOMEM;

        r = crypt_pbkdf("pbkdf2", "sha512",
                        pwd_utf16, pwd_utf16_length,
                        enchdr->salt, DCRYPTOR_HDR_SALT_LEN,
                        key, DCRYPTOR_HDR_KEY_LEN * chain_length,
                        1000, 0, 0);

        for (i = 0; dcryptor_cipher[i].chain_length; i++) {
                if (dcryptor_cipher[i].chain_length != chain_length)
                        continue;

                r = DCRYPTOR_decrypt_hdr_one_combination(key, enchdr, hdr,
                        &dcryptor_cipher[i]);
                if (r == 0) {
                        // found!
                        ret = 0;
                        *found_combination = i;
                        break;
                }

                if (r < 0) {
                        // error!
                        ret = r;
                        break;
                }
        }

	if (key)
		crypt_safe_memzero(key, DCRYPTOR_HDR_KEY_LEN * chain_length);

        free(key);
        return ret;
}

int DCRYPTOR_decrypt_hdr(struct crypt_device *cd,
			   struct dcryptor_enchdr *enchdr,
			   struct dcryptor_phdr *hdr,
			   struct crypt_params_dcryptor *params)
{
        int r;
        int i;
        int found_combination;

	assert(sizeof(struct dcryptor_enchdr) == DCRYPTOR_HDR_LEN);
	assert(sizeof(struct dcryptor_phdr) == DCRYPTOR_HDR_LEN);

        char *utf16Password = NULL;
        r = passphrase_to_utf16(cd, CONST_CAST(char *) params->passphrase, params->passphrase_size, &utf16Password);
        // TODO: check r

        for (i = 1 ; i <= 3; i++) {
                r = DCRYPTOR_decrypt_hdr_one_chain_length(cd, enchdr, hdr,
                        utf16Password, params->passphrase_size * 2,
                        i,
                        &found_combination);

                if (r <= 0)
                        break;
        }
        // TODO: if (r < 0) ...

        if (r == 0) {
                log_std(cd, "DONE\n");
                // hexprint(cd, hdr, 2048, " ");

                hexdump_buffer(stderr, (const unsigned char *)hdr, 2048, 16);
        }

        // TODO: little-endian vs big-endian

        return r;
}

int DCRYPTOR_decrypt_sector(struct crypt_device *cd,
                struct dcryptor_phdr *hdr,
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

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), sector, DCRYPTOR_HDR_LEN, sector_number * 512)
                        != 512) {

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

int DCRYPTOR_read_phdr(struct crypt_device *cd,
		     struct dcryptor_phdr *hdr,
		     struct crypt_params_dcryptor *params)
{
        int r = 0;
        int devfd;
	struct device *device = crypt_data_device(cd);
        struct dcryptor_enchdr *enchdr;

        devfd = device_open(cd, device, O_RDONLY);
	if (devfd < 0) {
		device_free(cd, device);
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

        enchdr = malloc(sizeof(struct dcryptor_enchdr));
        // TODO: if (enchdr == NULL)

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), enchdr, DCRYPTOR_HDR_LEN, 0) == DCRYPTOR_HDR_LEN) {
		r = DCRYPTOR_decrypt_hdr(cd, enchdr, hdr, params);

                //DCRYPTOR_decrypt_sector(cd, hdr, 16380);
        }

	if (r < 0)
		memset(hdr, 0, sizeof (*hdr));

        free(enchdr);
	return r;
}
