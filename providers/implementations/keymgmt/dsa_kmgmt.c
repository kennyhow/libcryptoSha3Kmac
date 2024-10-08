/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "prov/securitycheck.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "crypto/dsa.h"
#include "internal/sizes.h"
#include "internal/nelem.h"
#include "internal/param_build_set.h"

static OSSL_FUNC_keymgmt_new_fn dsa_newdata;
static OSSL_FUNC_keymgmt_free_fn dsa_freedata;
static OSSL_FUNC_keymgmt_gen_init_fn dsa_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn dsa_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn dsa_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn dsa_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_get_params_fn dsa_gen_get_params;
static OSSL_FUNC_keymgmt_gen_gettable_params_fn dsa_gen_gettable_params;
static OSSL_FUNC_keymgmt_gen_fn dsa_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn dsa_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn dsa_load;
static OSSL_FUNC_keymgmt_get_params_fn dsa_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn dsa_gettable_params;
static OSSL_FUNC_keymgmt_has_fn dsa_has;
static OSSL_FUNC_keymgmt_match_fn dsa_match;
static OSSL_FUNC_keymgmt_validate_fn dsa_validate;
static OSSL_FUNC_keymgmt_import_fn dsa_import;
static OSSL_FUNC_keymgmt_import_types_fn dsa_import_types;
static OSSL_FUNC_keymgmt_export_fn dsa_export;
static OSSL_FUNC_keymgmt_export_types_fn dsa_export_types;
static OSSL_FUNC_keymgmt_dup_fn dsa_dup;

#define DSA_DEFAULT_MD "SHA256"
#define DSA_POSSIBLE_SELECTIONS                                                \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

struct dsa_gen_ctx {
    OSSL_LIB_CTX *libctx;

    void *ffc_params;
    int selection;
    /* All these parameters are used for parameter generation only */
    size_t pbits;
    size_t qbits;
    unsigned char *seed; /* optional FIPS186-4 param for testing */
    size_t seedlen;
    int gindex; /* optional  FIPS186-4 generator index (ignored if -1) */
    int gen_type; /* DSA_PARAMGEN_TYPE_FIPS_186_2 or DSA_PARAMGEN_TYPE_FIPS_186_4 */
    int pcounter;
    int hindex;
    char *mdname;
    char *mdprops;
    OSSL_CALLBACK *cb;
    void *cbarg;
};
typedef struct dh_name2id_st{
    const char *name;
    int id;
} DSA_GENTYPE_NAME2ID;

static const DSA_GENTYPE_NAME2ID dsatype2id[] = {
#ifdef FIPS_MODULE
    { "default", DSA_PARAMGEN_TYPE_FIPS_186_4 },
#else
    { "default", DSA_PARAMGEN_TYPE_FIPS_DEFAULT },
#endif
    { "fips186_4", DSA_PARAMGEN_TYPE_FIPS_186_4 },
    { "fips186_2", DSA_PARAMGEN_TYPE_FIPS_186_2 },
};

static int dsa_gen_type_name2id(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dsatype2id); ++i) {
        if (OPENSSL_strcasecmp(dsatype2id[i].name, name) == 0)
            return dsatype2id[i].id;
    }
    return -1;
}

static int dsa_key_todata(DSA *dsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[],
                          int include_private)
{
    const BIGNUM *priv = NULL, *pub = NULL;

    if (dsa == NULL)
        return 0;

    DSA_get0_key(dsa, &pub, &priv);
    if (include_private
        && priv != NULL
        && !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PRIV_KEY, priv))
        return 0;
    if (pub != NULL
        && !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PUB_KEY, pub))
        return 0;

    return 1;
}

static void *dsa_newdata(void *provctx)
{
    if (!ossl_prov_is_running())
        return NULL;
    return ossl_dsa_new(PROV_LIBCTX_OF(provctx));
}

static void dsa_freedata(void *keydata)
{
    DSA_free(keydata);
}

static int dsa_has(const void *keydata, int selection)
{
    const DSA *dsa = keydata;
    int ok = 1;

    if (!ossl_prov_is_running() || dsa == NULL)
        return 0;
    if ((selection & DSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (DSA_get0_pub_key(dsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (DSA_get0_priv_key(dsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (DSA_get0_p(dsa) != NULL && DSA_get0_g(dsa) != NULL);
    return ok;
}

static int dsa_match(const void *keydata1, const void *keydata2, int selection)
{
    return 0;
}

static int dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    return 0;
}

static int dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    return 0;
}

/* IMEXPORT = IMPORT + EXPORT */

# define DSA_IMEXPORTABLE_PARAMETERS                                           \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),                      \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),                          \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),                        \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),                               \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0)
# define DSA_IMEXPORTABLE_PUBLIC_KEY                    \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define DSA_IMEXPORTABLE_PRIVATE_KEY                   \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
static const OSSL_PARAM dsa_all_types[] = {
    DSA_IMEXPORTABLE_PARAMETERS,
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM dsa_parameter_types[] = {
    DSA_IMEXPORTABLE_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM dsa_key_types[] = {
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM *dsa_types[] = {
    NULL,                        /* Index 0 = none of them */
    dsa_parameter_types,          /* Index 1 = parameter types */
    dsa_key_types,                /* Index 2 = key types */
    dsa_all_types                 /* Index 3 = 1 + 2 */
};

static const OSSL_PARAM *dsa_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        type_select += 2;
    return dsa_types[type_select];
}

static const OSSL_PARAM *dsa_import_types(int selection)
{
    return dsa_imexport_types(selection);
}

static const OSSL_PARAM *dsa_export_types(int selection)
{
    return dsa_imexport_types(selection);
}

static ossl_inline int dsa_get_params(void *key, OSSL_PARAM params[])
{
    return 0;
}

static const OSSL_PARAM dsa_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    DSA_IMEXPORTABLE_PARAMETERS,
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};

static const OSSL_PARAM *dsa_gettable_params(void *provctx)
{
    return dsa_params;
}

static int dsa_validate_domparams(const DSA *dsa, int checktype)
{
    int status = 0;

    return ossl_dsa_check_params(dsa, checktype, &status);
}

static int dsa_validate_public(const DSA *dsa)
{
    int status = 0;
    const BIGNUM *pub_key = NULL;

    DSA_get0_key(dsa, &pub_key, NULL);
    if (pub_key == NULL)
        return 0;
    return ossl_dsa_check_pub_key(dsa, pub_key, &status);
}

static int dsa_validate_private(const DSA *dsa)
{
    int status = 0;
    const BIGNUM *priv_key = NULL;

    DSA_get0_key(dsa, NULL, &priv_key);
    if (priv_key == NULL)
        return 0;
    return ossl_dsa_check_priv_key(dsa, priv_key, &status);
}

static int dsa_validate(const void *keydata, int selection, int checktype)
{
    const DSA *dsa = keydata;
    int ok = 1;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & DSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && dsa_validate_domparams(dsa, checktype);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && dsa_validate_public(dsa);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && dsa_validate_private(dsa);

    /* If the whole key is selected, we do a pairwise validation */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && ossl_dsa_check_pairwise(dsa);
    return ok;
}

static void *dsa_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct dsa_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running() || (selection & DSA_POSSIBLE_SELECTIONS) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->selection = selection;
        gctx->libctx = libctx;
        gctx->pbits = 2048;
        gctx->qbits = 224;
#ifdef FIPS_MODULE
        gctx->gen_type = DSA_PARAMGEN_TYPE_FIPS_186_4;
#else
        gctx->gen_type = DSA_PARAMGEN_TYPE_FIPS_DEFAULT;
#endif
        gctx->gindex = -1;
        gctx->pcounter = -1;
        gctx->hindex = 0;
    }
    if (!dsa_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx);
        gctx = NULL;
    }
    return gctx;
}

static int dsa_gen_set_template(void *genctx, void *templ)
{
    return 0;
}

static int dsa_set_gen_seed(struct dsa_gen_ctx *gctx, unsigned char *seed,
                            size_t seedlen)
{
    OPENSSL_clear_free(gctx->seed, gctx->seedlen);
    gctx->seed = NULL;
    gctx->seedlen = 0;
    if (seed != NULL && seedlen > 0) {
        gctx->seed = OPENSSL_memdup(seed, seedlen);
        if (gctx->seed == NULL)
            return 0;
        gctx->seedlen = seedlen;
    }
    return 1;
}

static int dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct dsa_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;
    int gen_type = -1;

    if (gctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || ((gen_type = dsa_gen_type_name2id(p->data)) == -1)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }

        /*
         * Only assign context gen_type if it was set by dsa_gen_type_name2id
         * must be in range:
         * DSA_PARAMGEN_TYPE_FIPS_186_4 <= gen_type <= DSA_PARAMGEN_TYPE_FIPS_DEFAULT
         */
        if (gen_type != -1)
            gctx->gen_type = gen_type;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
    if (p != NULL
        && !OSSL_PARAM_get_int(p, &gctx->gindex))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
    if (p != NULL
        && !OSSL_PARAM_get_int(p, &gctx->pcounter))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
    if (p != NULL
        && !OSSL_PARAM_get_int(p, &gctx->hindex))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
    if (p != NULL
        && (p->data_type != OSSL_PARAM_OCTET_STRING
            || !dsa_set_gen_seed(gctx, p->data, p->data_size)))
            return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->pbits))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->qbits))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->mdname);
        gctx->mdname = OPENSSL_strdup(p->data);
        if (gctx->mdname == NULL)
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->mdprops);
        gctx->mdprops = OPENSSL_strdup(p->data);
        if (gctx->mdprops == NULL)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *dsa_gen_settable_params(ossl_unused void *genctx,
                                                 ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, NULL, 0),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_QBITS, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
        OSSL_PARAM_END
    };
    return settable;
}

static int dsa_gen_get_params(void *genctx, OSSL_PARAM *params)
{
    struct dsa_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return 0;
    if (params == NULL)
        return 1;
    return 1;
}

static const OSSL_PARAM *dsa_gen_gettable_params(ossl_unused void *ctx,
                                                 ossl_unused void *provctx)
{
    static const OSSL_PARAM dsa_gen_gettable_params_table[] = {
        OSSL_PARAM_END
    };

    return dsa_gen_gettable_params_table;
}

static int dsa_gencb(int p, int n, BN_GENCB *cb)
{
    struct dsa_gen_ctx *gctx = BN_GENCB_get_arg(cb);
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    return gctx->cb(params, gctx->cbarg);
}

static void *dsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    return 0;
}

static void dsa_gen_cleanup(void *genctx)
{
    struct dsa_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;

    OPENSSL_free(gctx->mdname);
    OPENSSL_free(gctx->mdprops);
    OPENSSL_clear_free(gctx->seed, gctx->seedlen);
    OPENSSL_free(gctx);
}

static void *dsa_load(const void *reference, size_t reference_sz)
{
    DSA *dsa = NULL;

    if (ossl_prov_is_running() && reference_sz == sizeof(dsa)) {
        /* The contents of the reference is the address to our object */
        dsa = *(DSA **)reference;
        /* We grabbed, so we detach it */
        *(DSA **)reference = NULL;
        return dsa;
    }
    return NULL;
}

static void *dsa_dup(const void *keydata_from, int selection)
{
    if (ossl_prov_is_running())
        return ossl_dsa_dup(keydata_from, selection);
    return NULL;
}

const OSSL_DISPATCH ossl_dsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dsa_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))dsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))dsa_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))dsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))dsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void))dsa_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
      (void (*)(void))dsa_gen_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))dsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))dsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))dsa_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))dsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))dsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))dsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))dsa_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dsa_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))dsa_dup },
    OSSL_DISPATCH_END
};
