/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/provider_util.h"
#include "prov/seeding.h"
#include "internal/nelem.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn deflt_gettable_params;
static OSSL_FUNC_provider_get_params_fn deflt_get_params;
static OSSL_FUNC_provider_query_operation_fn deflt_query;

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM deflt_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *deflt_gettable_params(void *provctx)
{
    return deflt_param_types;
}

static int deflt_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Default Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

/*
 * For the algorithm names, we use the following formula for our primary
 * names:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 *
 * We add diverse other names where applicable, such as the names that
 * NIST uses, or that are used for ASN.1 OBJECT IDENTIFIERs, or names
 * we have used historically.
 *
 * Algorithm names are case insensitive, but we use all caps in our "canonical"
 * names for consistency.
 */
static const OSSL_ALGORITHM deflt_digests[] = {
    /* Our primary name:NIST name[:our older names] */
    { PROV_NAMES_SHA1, "provider=default", ossl_sha1_functions },
    { PROV_NAMES_SHA2_224, "provider=default", ossl_sha224_functions },
    { PROV_NAMES_SHA2_256, "provider=default", ossl_sha256_functions },
    { PROV_NAMES_SHA2_256_192, "provider=default", ossl_sha256_192_functions },
    { PROV_NAMES_SHA2_384, "provider=default", ossl_sha384_functions },
    { PROV_NAMES_SHA2_512, "provider=default", ossl_sha512_functions },
    { PROV_NAMES_SHA2_512_224, "provider=default", ossl_sha512_224_functions },
    { PROV_NAMES_SHA2_512_256, "provider=default", ossl_sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { PROV_NAMES_SHA3_224, "provider=default", ossl_sha3_224_functions },
    { PROV_NAMES_SHA3_256, "provider=default", ossl_sha3_256_functions },
    { PROV_NAMES_SHA3_384, "provider=default", ossl_sha3_384_functions },
    { PROV_NAMES_SHA3_512, "provider=default", ossl_sha3_512_functions },

    { PROV_NAMES_KECCAK_224, "provider=default", ossl_keccak_224_functions },
    { PROV_NAMES_KECCAK_256, "provider=default", ossl_keccak_256_functions },
    { PROV_NAMES_KECCAK_384, "provider=default", ossl_keccak_384_functions },
    { PROV_NAMES_KECCAK_512, "provider=default", ossl_keccak_512_functions },

    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * the KMAC-128 and KMAC-256.
     */
    { PROV_NAMES_KECCAK_KMAC_128, "provider=default",
      ossl_keccak_kmac_128_functions },
    { PROV_NAMES_KECCAK_KMAC_256, "provider=default",
      ossl_keccak_kmac_256_functions },

    /* Our primary name:NIST name */
    { PROV_NAMES_SHAKE_128, "provider=default", ossl_shake_128_functions },
    { PROV_NAMES_SHAKE_256, "provider=default", ossl_shake_256_functions },

#ifndef OPENSSL_NO_BLAKE2
    /*
     * https://blake2.net/ doesn't specify size variants,
     * but mentions that Bouncy Castle uses the names
     * BLAKE2b-160, BLAKE2b-256, BLAKE2b-384, and BLAKE2b-512
     * If we assume that "2b" and "2s" are versions, that pattern
     * fits with ours.  We also add our historical names.
     */
    { PROV_NAMES_BLAKE2S_256, "provider=default", ossl_blake2s256_functions },
    { PROV_NAMES_BLAKE2B_512, "provider=default", ossl_blake2b512_functions },
#endif /* OPENSSL_NO_BLAKE2 */

#ifndef OPENSSL_NO_SM3
    { PROV_NAMES_SM3, "provider=default", ossl_sm3_functions },
#endif /* OPENSSL_NO_SM3 */

#ifndef OPENSSL_NO_MD5
    { PROV_NAMES_MD5, "provider=default", ossl_md5_functions },
    { PROV_NAMES_MD5_SHA1, "provider=default", ossl_md5_sha1_functions },
#endif /* OPENSSL_NO_MD5 */

#ifndef OPENSSL_NO_RMD160
    { PROV_NAMES_RIPEMD_160, "provider=default", ossl_ripemd160_functions },
#endif /* OPENSSL_NO_RMD160 */

    { PROV_NAMES_NULL, "provider=default", ossl_nullmd_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_macs[] = {
#ifndef OPENSSL_NO_BLAKE2
    { PROV_NAMES_BLAKE2BMAC, "provider=default", ossl_blake2bmac_functions },
    { PROV_NAMES_BLAKE2SMAC, "provider=default", ossl_blake2smac_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, "provider=default", ossl_cmac_functions },
#endif
    { PROV_NAMES_GMAC, "provider=default", ossl_gmac_functions },
    { PROV_NAMES_HMAC, "provider=default", ossl_hmac_functions },
    { PROV_NAMES_KMAC_128, "provider=default", ossl_kmac128_functions },
    { PROV_NAMES_KMAC_256, "provider=default", ossl_kmac256_functions },
#ifndef OPENSSL_NO_SIPHASH
    { PROV_NAMES_SIPHASH, "provider=default", ossl_siphash_functions },
#endif
#ifndef OPENSSL_NO_POLY1305
    { PROV_NAMES_POLY1305, "provider=default", ossl_poly1305_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_kdfs[] = {
    { PROV_NAMES_HKDF, "provider=default", ossl_kdf_hkdf_functions },
    { PROV_NAMES_TLS1_3_KDF, "provider=default",
      ossl_kdf_tls1_3_kdf_functions },
    { PROV_NAMES_SSKDF, "provider=default", ossl_kdf_sskdf_functions },
    { PROV_NAMES_PBKDF2, "provider=default", ossl_kdf_pbkdf2_functions },
    { PROV_NAMES_PKCS12KDF, "provider=default", ossl_kdf_pkcs12_functions },
    { PROV_NAMES_SSHKDF, "provider=default", ossl_kdf_sshkdf_functions },
    { PROV_NAMES_X963KDF, "provider=default", ossl_kdf_x963_kdf_functions },
    { PROV_NAMES_TLS1_PRF, "provider=default", ossl_kdf_tls1_prf_functions },
    { PROV_NAMES_KBKDF, "provider=default", ossl_kdf_kbkdf_functions },
    { PROV_NAMES_X942KDF_ASN1, "provider=default", ossl_kdf_x942_kdf_functions },
#ifndef OPENSSL_NO_SCRYPT
    { PROV_NAMES_SCRYPT, "provider=default", ossl_kdf_scrypt_functions },
#endif
    { PROV_NAMES_KRB5KDF, "provider=default", ossl_kdf_krb5kdf_functions },
    { PROV_NAMES_HMAC_DRBG_KDF, "provider=default",
      ossl_kdf_hmac_drbg_functions },
#ifndef OPENSSL_NO_ARGON2
    { PROV_NAMES_ARGON2I, "provider=default", ossl_kdf_argon2i_functions },
    { PROV_NAMES_ARGON2D, "provider=default", ossl_kdf_argon2d_functions },
    { PROV_NAMES_ARGON2ID, "provider=default", ossl_kdf_argon2id_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { PROV_NAMES_DH, "provider=default", ossl_dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_ECDH, "provider=default", ossl_ecdh_keyexch_functions },
# ifndef OPENSSL_NO_ECX
    { PROV_NAMES_X25519, "provider=default", ossl_x25519_keyexch_functions },
    { PROV_NAMES_X448, "provider=default", ossl_x448_keyexch_functions },
# endif
#endif
    { PROV_NAMES_TLS1_PRF, "provider=default", ossl_kdf_tls1_prf_keyexch_functions },
    { PROV_NAMES_HKDF, "provider=default", ossl_kdf_hkdf_keyexch_functions },
    { PROV_NAMES_SCRYPT, "provider=default",
      ossl_kdf_scrypt_keyexch_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_rands[] = {
    { PROV_NAMES_CTR_DRBG, "provider=default", ossl_drbg_ctr_functions },
    { PROV_NAMES_HASH_DRBG, "provider=default", ossl_drbg_hash_functions },
    { PROV_NAMES_HMAC_DRBG, "provider=default", ossl_drbg_ossl_hmac_functions },
    { PROV_NAMES_SEED_SRC, "provider=default", ossl_seed_src_functions },
#ifndef OPENSSL_NO_JITTER
    { PROV_NAMES_JITTER, "provider=default", ossl_jitter_functions },
#endif
    { PROV_NAMES_TEST_RAND, "provider=default", ossl_test_rng_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_signature[] = {
#ifndef OPENSSL_NO_DSA
    { PROV_NAMES_DSA, "provider=default", ossl_dsa_signature_functions },
#endif
    { PROV_NAMES_RSA, "provider=default", ossl_rsa_signature_functions },
#if !defined(OPENSSL_NO_RMD160) && !defined(FIPS_MODULE)
    { PROV_NAMES_RSA_RIPEMD160, "provider=default", ossl_rsa_ripemd160_signature_functions },
#endif
    { PROV_NAMES_RSA_SHA1, "provider=default", ossl_rsa_sha1_signature_functions },
    { PROV_NAMES_RSA_SHA224, "provider=default", ossl_rsa_sha224_signature_functions },
    { PROV_NAMES_RSA_SHA256, "provider=default", ossl_rsa_sha256_signature_functions },
    { PROV_NAMES_RSA_SHA384, "provider=default", ossl_rsa_sha384_signature_functions },
    { PROV_NAMES_RSA_SHA512, "provider=default", ossl_rsa_sha512_signature_functions },
    { PROV_NAMES_RSA_SHA512_224, "provider=default", ossl_rsa_sha512_224_signature_functions },
    { PROV_NAMES_RSA_SHA512_256, "provider=default", ossl_rsa_sha512_256_signature_functions },
    { PROV_NAMES_RSA_SHA3_224, "provider=default", ossl_rsa_sha3_224_signature_functions },
    { PROV_NAMES_RSA_SHA3_256, "provider=default", ossl_rsa_sha3_256_signature_functions },
    { PROV_NAMES_RSA_SHA3_384, "provider=default", ossl_rsa_sha3_384_signature_functions },
    { PROV_NAMES_RSA_SHA3_512, "provider=default", ossl_rsa_sha3_512_signature_functions },
#ifndef OPENSSL_NO_SM3
    { PROV_NAMES_RSA_SM3, "provider=default", ossl_rsa_sm3_signature_functions },
#endif
#ifndef OPENSSL_NO_EC
# ifndef OPENSSL_NO_ECX
    { PROV_NAMES_ED25519, "provider=default", ossl_ed25519_signature_functions },
    { PROV_NAMES_ED448, "provider=default", ossl_ed448_signature_functions },
# endif
    { PROV_NAMES_ECDSA, "provider=default", ossl_ecdsa_signature_functions },
# ifndef OPENSSL_NO_SM2
    { PROV_NAMES_SM2, "provider=default", ossl_sm2_signature_functions },
# endif
#endif
    { PROV_NAMES_HMAC, "provider=default", ossl_mac_legacy_hmac_signature_functions },
    { PROV_NAMES_SIPHASH, "provider=default",
      ossl_mac_legacy_siphash_signature_functions },
#ifndef OPENSSL_NO_POLY1305
    { PROV_NAMES_POLY1305, "provider=default",
      ossl_mac_legacy_poly1305_signature_functions },
#endif
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, "provider=default", ossl_mac_legacy_cmac_signature_functions },
#endif
    { NULL, NULL, NULL }
};


static const OSSL_ALGORITHM deflt_asym_kem[] = {
    { PROV_NAMES_RSA, "provider=default", ossl_rsa_asym_kem_functions },
#ifndef OPENSSL_NO_EC
# ifndef OPENSSL_NO_ECX
    { PROV_NAMES_X25519, "provider=default", ossl_ecx_asym_kem_functions },
    { PROV_NAMES_X448, "provider=default", ossl_ecx_asym_kem_functions },
# endif
    { PROV_NAMES_EC, "provider=default", ossl_ec_asym_kem_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { PROV_NAMES_DH, "provider=default", ossl_dh_keymgmt_functions,
      PROV_DESCS_DH },
    { PROV_NAMES_DHX, "provider=default", ossl_dhx_keymgmt_functions,
      PROV_DESCS_DHX },
#endif
#ifndef OPENSSL_NO_DSA
    { PROV_NAMES_DSA, "provider=default", ossl_dsa_keymgmt_functions,
      PROV_DESCS_DSA},
#endif
    { PROV_NAMES_RSA, "provider=default", ossl_rsa_keymgmt_functions,
      PROV_DESCS_RSA },
    { PROV_NAMES_RSA_PSS, "provider=default", ossl_rsapss_keymgmt_functions,
      PROV_DESCS_RSA_PSS },
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_EC, "provider=default", ossl_ec_keymgmt_functions,
      PROV_DESCS_EC },
# ifndef OPENSSL_NO_ECX
    { PROV_NAMES_X25519, "provider=default", ossl_x25519_keymgmt_functions,
      PROV_DESCS_X25519 },
    { PROV_NAMES_X448, "provider=default", ossl_x448_keymgmt_functions,
      PROV_DESCS_X448 },
    { PROV_NAMES_ED25519, "provider=default", ossl_ed25519_keymgmt_functions,
      PROV_DESCS_ED25519 },
    { PROV_NAMES_ED448, "provider=default", ossl_ed448_keymgmt_functions,
      PROV_DESCS_ED448 },
# endif
#endif
    { PROV_NAMES_TLS1_PRF, "provider=default", ossl_kdf_keymgmt_functions,
      PROV_DESCS_TLS1_PRF_SIGN },
    { PROV_NAMES_HKDF, "provider=default", ossl_kdf_keymgmt_functions,
      PROV_DESCS_HKDF_SIGN },
    { PROV_NAMES_SCRYPT, "provider=default", ossl_kdf_keymgmt_functions,
      PROV_DESCS_SCRYPT_SIGN },
    { PROV_NAMES_HMAC, "provider=default", ossl_mac_legacy_keymgmt_functions,
      PROV_DESCS_HMAC_SIGN },
    { PROV_NAMES_SIPHASH, "provider=default", ossl_mac_legacy_keymgmt_functions,
      PROV_DESCS_SIPHASH_SIGN },
#ifndef OPENSSL_NO_POLY1305
    { PROV_NAMES_POLY1305, "provider=default", ossl_mac_legacy_keymgmt_functions,
      PROV_DESCS_POLY1305_SIGN },
#endif
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, "provider=default", ossl_cmac_legacy_keymgmt_functions,
      PROV_DESCS_CMAC_SIGN },
#endif
#ifndef OPENSSL_NO_SM2
    { PROV_NAMES_SM2, "provider=default", ossl_sm2_keymgmt_functions,
      PROV_DESCS_SM2 },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_encoder[] = {
#define ENCODER_PROVIDER "default"
#include "encoders.inc"
    { NULL, NULL, NULL }
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM deflt_decoder[] = {
#define DECODER_PROVIDER "default"
#include "decoders.inc"
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};

static const OSSL_ALGORITHM deflt_store[] = {
#define STORE(name, _fips, func_table)                           \
    { name, "provider=default,fips=" _fips, (func_table) },

#include "stores.inc"
    { NULL, NULL, NULL }
#undef STORE
};

static const OSSL_ALGORITHM *deflt_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return deflt_digests;
    case OSSL_OP_MAC:
        return deflt_macs;
    case OSSL_OP_KDF:
        return deflt_kdfs;
    case OSSL_OP_RAND:
        return deflt_rands;
    case OSSL_OP_KEYMGMT:
        return deflt_keymgmt;
    case OSSL_OP_KEYEXCH:
        return deflt_keyexch;
    case OSSL_OP_SIGNATURE:
        return deflt_signature;
    case OSSL_OP_KEM:
        return deflt_asym_kem;
    case OSSL_OP_ENCODER:
        return deflt_encoder;
    case OSSL_OP_DECODER:
        return deflt_decoder;
    case OSSL_OP_STORE:
        return deflt_store;
    }
    return NULL;
}


static void deflt_teardown(void *provctx)
{
    BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx));
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH deflt_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))deflt_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))deflt_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))deflt_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))deflt_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))ossl_prov_get_capabilities },
    OSSL_DISPATCH_END
};

OSSL_provider_init_fn ossl_default_provider_init;

int ossl_default_provider_init(const OSSL_CORE_HANDLE *handle,
                               const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out,
                               void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    BIO_METHOD *corebiometh;

    if (!ossl_prov_bio_from_dispatch(in)
            || !ossl_prov_seeding_from_dispatch(in))
        return 0;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     *
     * This only works for built-in providers.  Most providers should
     * create their own library context.
     */
    if ((*provctx = ossl_prov_ctx_new()) == NULL
            || (corebiometh = ossl_bio_prov_init_bio_method()) == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx,
                                       (OSSL_LIB_CTX *)c_get_libctx(handle));
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_core_bio_method(*provctx, corebiometh);

    *out = deflt_dispatch_table;
    return 1;
}
