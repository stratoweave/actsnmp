// C implementation of usmcrypto.act.
//
// This file is #included into the C file that Acton generates for the
// module, so static helpers stay private to it. Exported names follow the
// pattern snmpQ_usmcryptoQ_<name> (project "snmp", module "usmcrypto").
//
// The mbedtls headers come from deps/mbedtls_headers and the mbedtls objects
// from libActon, so they always match each other.
//
// Conventions for every function in this file (keep them when extending):
//   * Validate all arguments first. Bad input raises ValueError through
//     raise_value_error() (or require_len()); a failing mbedtls call raises
//     through raise_mbedtls_error(). Both use $FORMAT, so messages can carry
//     values.
//   * RAISE is a longjmp: code after it never runs. Free mbedtls contexts
//     and wipe buffers holding secrets before raising, so the order is:
//     validate, compute, clean up, and only then check the return code and
//     raise.
//   * Map a HASH_* id to mbedtls with md_info_for(), which raises for an
//     unknown id. The ids are defined in usmcrypto.act and must stay in sync
//     with md_type_for() below.
//   * Small fixed-size results (digests, keys) are computed into a local
//     buffer and returned through bytes_from_buf(), which copies them into
//     GC-managed storage, so the local copy can be wiped. Results as long as
//     the input (ciphertext, plaintext, random bytes) are written straight
//     into the storage of the returned bytes object, allocated with
//     new_bytes(). Do not keep pointers to Acton objects in C state, and do
//     not keep C state between calls: the runtime runs actors on many
//     threads.
//   * Wipe local buffers that held key material, keystream or results
//     (digests are used as keys in USM key derivation) with
//     mbedtls_platform_zeroize() once they are no longer needed. The
//     mbedtls_*_free() functions wipe their contexts, and mbedtls itself
//     wipes the contexts used by mbedtls_md() and mbedtls_md_hmac().

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>

#include <mbedtls/aes.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/des.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

void snmpQ_usmcryptoQ___ext_init__() {}

// --- helpers ------------------------------------------------------------------

static struct B_MemoryError alloc_failed_error =
    STATIC_EXCEPTION(B_MemoryError, "usmcrypto: out of memory");

static void raise_value_error(B_str msg) {
    RAISE(B_ValueError, msg);
}

static void raise_mbedtls_error(const char *what, int rc) {
    RAISE(B_ValueError, $FORMAT("usmcrypto: %s failed: -0x%04x", what, (unsigned int)-rc));
}

// Raise ValueError unless argument arg of function fn is exactly len bytes.
static void require_len(const char *fn, const char *arg, B_bytes b, int64_t len) {
    if (b->nbytes != len)
        raise_value_error($FORMAT("usmcrypto: %s: %s must be %lld bytes, got %lld",
                                  fn, arg, (long long)len, (long long)b->nbytes));
}

// Copy len bytes from buf into a new Acton bytes object.
static B_bytes bytes_from_buf(const unsigned char *buf, size_t len) {
    return actBytesFromCStringLengthCopy((const char *)buf, (int64_t)len);
}

// Return a new bytes object of n bytes whose content the caller then writes
// through *buf. The storage is GC-managed and pointer-free, so there is
// nothing to free if the caller raises before filling it in.
static B_bytes new_bytes(int64_t n, unsigned char **buf) {
    // one spare byte keeps *buf a valid pointer when n is 0
    unsigned char *p = acton_malloc_atomic((size_t)n + 1);
    if (p == NULL)
        RAISE_EXC(&alloc_failed_error);
    *buf = p;
    return actBytesFromCStringLengthNoCopy((char *)p, n);
}

// HASH_* id (usmcrypto.act) -> mbedtls digest type, MBEDTLS_MD_NONE if unknown.
static mbedtls_md_type_t md_type_for(int64_t alg) {
    switch (alg) {
    case 1: return MBEDTLS_MD_MD5;      // HASH_MD5
    case 2: return MBEDTLS_MD_SHA1;     // HASH_SHA1
    case 3: return MBEDTLS_MD_SHA224;   // HASH_SHA224
    case 4: return MBEDTLS_MD_SHA256;   // HASH_SHA256
    case 5: return MBEDTLS_MD_SHA384;   // HASH_SHA384
    case 6: return MBEDTLS_MD_SHA512;   // HASH_SHA512
    default: return MBEDTLS_MD_NONE;
    }
}

// mbedtls digest info for a HASH_* id. Raises ValueError for an unknown id or
// a digest that the linked mbedtls was built without.
static const mbedtls_md_info_t *md_info_for(int64_t alg) {
    mbedtls_md_type_t t = md_type_for(alg);
    const mbedtls_md_info_t *info = t == MBEDTLS_MD_NONE ? NULL : mbedtls_md_info_from_type(t);
    if (info == NULL)
        raise_value_error($FORMAT("usmcrypto: unsupported hash algorithm: %lld", (long long)alg));
    return info;
}

// DES-CBC (key_len 8) or 3DES-EDE-CBC (key_len 24) over whole blocks.
// mode is MBEDTLS_DES_ENCRYPT or MBEDTLS_DES_DECRYPT; fn names the exported
// function in error messages.
static B_bytes des_cbc(const char *fn, int64_t key_len, int mode, B_bytes key, B_bytes iv, B_bytes data) {
    require_len(fn, "key", key, key_len);
    require_len(fn, "iv", iv, 8);
    if (data->nbytes % 8 != 0)
        raise_value_error($FORMAT("usmcrypto: %s: data length must be a multiple of 8, got %lld",
                                  fn, (long long)data->nbytes));
    size_t len = (size_t)data->nbytes;
    unsigned char *out;
    B_bytes res = new_bytes(data->nbytes, &out);
    // mbedtls advances the IV in place; never let it write to the caller's bytes
    unsigned char ivbuf[8];
    memcpy(ivbuf, iv->str, sizeof(ivbuf));
    int rc;
    if (key_len == 24) {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        rc = mode == MBEDTLS_DES_ENCRYPT ? mbedtls_des3_set3key_enc(&ctx, key->str)
                                         : mbedtls_des3_set3key_dec(&ctx, key->str);
        if (rc == 0)
            rc = mbedtls_des3_crypt_cbc(&ctx, mode, len, ivbuf, data->str, out);
        mbedtls_des3_free(&ctx);
    } else {
        mbedtls_des_context ctx;
        mbedtls_des_init(&ctx);
        rc = mode == MBEDTLS_DES_ENCRYPT ? mbedtls_des_setkey_enc(&ctx, key->str)
                                         : mbedtls_des_setkey_dec(&ctx, key->str);
        if (rc == 0)
            rc = mbedtls_des_crypt_cbc(&ctx, mode, len, ivbuf, data->str, out);
        mbedtls_des_free(&ctx);
    }
    mbedtls_platform_zeroize(ivbuf, sizeof(ivbuf));
    if (rc != 0) {
        mbedtls_platform_zeroize(out, len);
        raise_mbedtls_error(fn, rc);
    }
    return res;
}

// AES-CFB128 with a 16, 24 or 32 byte key; any data length.
// mode is MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT.
static B_bytes aes_cfb128(const char *fn, int mode, B_bytes key, B_bytes iv, B_bytes data) {
    if (key->nbytes != 16 && key->nbytes != 24 && key->nbytes != 32)
        raise_value_error($FORMAT("usmcrypto: %s: key must be 16, 24 or 32 bytes, got %lld",
                                  fn, (long long)key->nbytes));
    require_len(fn, "iv", iv, 16);
    size_t len = (size_t)data->nbytes;
    unsigned char *out;
    B_bytes res = new_bytes(data->nbytes, &out);
    // mbedtls advances the IV in place (after a partial last block it holds
    // unused keystream), so work on a local copy and wipe it afterwards
    unsigned char ivbuf[16];
    memcpy(ivbuf, iv->str, sizeof(ivbuf));
    size_t iv_off = 0;
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    // CFB runs the block cipher forward in both directions, so decryption
    // uses the encryption key schedule too
    int rc = mbedtls_aes_setkey_enc(&ctx, key->str, (unsigned int)key->nbytes * 8);
    if (rc == 0)
        rc = mbedtls_aes_crypt_cfb128(&ctx, mode, len, &iv_off, ivbuf, data->str, out);
    mbedtls_aes_free(&ctx);
    mbedtls_platform_zeroize(ivbuf, sizeof(ivbuf));
    if (rc != 0) {
        mbedtls_platform_zeroize(out, len);
        raise_mbedtls_error(fn, rc);
    }
    return res;
}

// --- exported functions -------------------------------------------------------

B_bytes snmpQ_usmcryptoQ_hash (int64_t alg, B_bytes data) {
    const mbedtls_md_info_t *info = md_info_for(alg);
    unsigned char out[MBEDTLS_MD_MAX_SIZE];
    int rc = mbedtls_md(info, data->str, (size_t)data->nbytes, out);
    if (rc != 0)
        raise_mbedtls_error("mbedtls_md", rc);
    // digests are used as key material in USM key derivation
    B_bytes res = bytes_from_buf(out, mbedtls_md_get_size(info));
    mbedtls_platform_zeroize(out, sizeof(out));
    return res;
}

B_bytes snmpQ_usmcryptoQ_hmac (int64_t alg, B_bytes key, B_bytes data) {
    const mbedtls_md_info_t *info = md_info_for(alg);
    unsigned char out[MBEDTLS_MD_MAX_SIZE];
    int rc = mbedtls_md_hmac(info, key->str, (size_t)key->nbytes, data->str, (size_t)data->nbytes, out);
    if (rc != 0)
        raise_mbedtls_error("mbedtls_md_hmac", rc);
    B_bytes res = bytes_from_buf(out, mbedtls_md_get_size(info));
    mbedtls_platform_zeroize(out, sizeof(out));
    return res;
}

// RFC 3414 A.2 hashes exactly this many bytes of the repeated password.
#define P2K_TOTAL 1048576
// Feed the hash at least this many bytes per update.
#define P2K_CHUNK 4096

B_bytes snmpQ_usmcryptoQ_password_to_key (int64_t alg, B_bytes password) {
    const mbedtls_md_info_t *info = md_info_for(alg);
    if (password->nbytes == 0)
        raise_value_error($FORMAT("usmcrypto: password_to_key: password must not be empty"));
    size_t plen = (size_t)password->nbytes;

    // The input is the password repeated, so it is periodic with period plen.
    // Hash it from a buffer holding a whole number of copies: every update
    // then ends on a copy boundary and the next one continues the stream
    // exactly. A short password is doubled up to at least P2K_CHUNK bytes
    // (at most 2 * P2K_CHUNK - 2); a long one is used in place.
    unsigned char rep[2 * P2K_CHUNK];
    const unsigned char *src = password->str;
    size_t srclen = plen;
    if (plen < P2K_CHUNK) {
        memcpy(rep, password->str, plen);
        while (srclen < P2K_CHUNK) {
            memcpy(rep + srclen, rep, srclen);
            srclen *= 2;
        }
        src = rep;
    }

    unsigned char out[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int rc = mbedtls_md_setup(&ctx, info, 0);
    if (rc == 0)
        rc = mbedtls_md_starts(&ctx);
    for (size_t left = P2K_TOTAL; rc == 0 && left > 0; ) {
        size_t n = left < srclen ? left : srclen;
        rc = mbedtls_md_update(&ctx, src, n);
        left -= n;
    }
    if (rc == 0)
        rc = mbedtls_md_finish(&ctx, out);
    mbedtls_md_free(&ctx);
    if (src == rep)
        mbedtls_platform_zeroize(rep, srclen);
    if (rc != 0) {
        mbedtls_platform_zeroize(out, sizeof(out));
        raise_mbedtls_error("password_to_key", rc);
    }
    B_bytes res = bytes_from_buf(out, mbedtls_md_get_size(info));
    mbedtls_platform_zeroize(out, sizeof(out));
    return res;
}

B_bytes snmpQ_usmcryptoQ_des_cbc_encrypt (B_bytes key, B_bytes iv, B_bytes data) {
    return des_cbc("des_cbc_encrypt", 8, MBEDTLS_DES_ENCRYPT, key, iv, data);
}

B_bytes snmpQ_usmcryptoQ_des_cbc_decrypt (B_bytes key, B_bytes iv, B_bytes data) {
    return des_cbc("des_cbc_decrypt", 8, MBEDTLS_DES_DECRYPT, key, iv, data);
}

B_bytes snmpQ_usmcryptoQ_des3_cbc_encrypt (B_bytes key, B_bytes iv, B_bytes data) {
    return des_cbc("des3_cbc_encrypt", 24, MBEDTLS_DES_ENCRYPT, key, iv, data);
}

B_bytes snmpQ_usmcryptoQ_des3_cbc_decrypt (B_bytes key, B_bytes iv, B_bytes data) {
    return des_cbc("des3_cbc_decrypt", 24, MBEDTLS_DES_DECRYPT, key, iv, data);
}

B_bytes snmpQ_usmcryptoQ_aes_cfb128_encrypt (B_bytes key, B_bytes iv, B_bytes data) {
    return aes_cfb128("aes_cfb128_encrypt", MBEDTLS_AES_ENCRYPT, key, iv, data);
}

B_bytes snmpQ_usmcryptoQ_aes_cfb128_decrypt (B_bytes key, B_bytes iv, B_bytes data) {
    return aes_cfb128("aes_cfb128_decrypt", MBEDTLS_AES_DECRYPT, key, iv, data);
}

bool snmpQ_usmcryptoQ_ct_equal (B_bytes a, B_bytes b) {
    // lengths are public (MAC lengths are fixed per protocol); only the
    // content comparison must not leak where the first difference is
    if (a->nbytes != b->nbytes)
        return false;
    return mbedtls_ct_memcmp(a->str, b->str, (size_t)a->nbytes) == 0;
}

B_bytes snmpQ_usmcryptoQ_random_bytes (int64_t n) {
    if (n < 0)
        raise_value_error($FORMAT("usmcrypto: random_bytes: n must be >= 0, got %lld", (long long)n));
    if (n > MAX_STR_LEN)
        raise_value_error($FORMAT("usmcrypto: random_bytes: n too large: %lld", (long long)n));
    unsigned char *buf;
    B_bytes res = new_bytes(n, &buf);
    int64_t got = 0;
    while (got < n) {
        // getentropy() returns at most 256 bytes per call
        size_t chunk = (n - got) > 256 ? 256 : (size_t)(n - got);
        if (getentropy(buf + got, chunk) != 0) {
            if (errno == EINTR)
                continue;
            RAISE(B_OSError, $FORMAT("usmcrypto: getentropy failed: %s", strerror(errno)));
        }
        got += (int64_t)chunk;
    }
    return res;
}
