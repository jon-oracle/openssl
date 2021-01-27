/*
 * Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/decoder.h>
#include "testutil.h"
#include "helpers/testdata.h"
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "crypto/evp.h"
#include "../e_os.h" /* strcasecmp */

static OSSL_LIB_CTX *testctx = NULL;

#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_DH)
static EVP_PKEY *load_ffc_priv_key_params(const char *keytype)
{   
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(NULL, keytype, NULL)))
        goto err;
    
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, td_get0_ffc_p_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, td_get0_ffc_q_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, td_get0_ffc_g_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             td_get0_ffc_pub_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             td_get0_ffc_priv_bn())))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;
    
    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params), 0))
        goto err;
    
    if (!TEST_ptr(pkey))
        goto err;

err:
    OSSL_PARAM_BLD_free_params(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
#endif /* !OPENSSL_NO_DSA || !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_DSA
static EVP_PKEY *load_dsa_priv_key_legacy(void)
{
    EVP_PKEY *pkey = NULL;
    DSA *dsa = NULL;

    pkey = EVP_PKEY_new();
    if (!TEST_ptr(pkey))
        goto end;

    dsa = DSA_new();
    if (!TEST_ptr(dsa))
        goto end;

    if (!TEST_true(DSA_set0_pqg(dsa, td_get1_ffc_p_bn(), td_get1_ffc_q_bn(), td_get1_ffc_g_bn())))
        goto end;

    if (!TEST_true(DSA_set0_key(dsa, td_get1_ffc_priv_bn(), td_get1_ffc_pub_bn())))
        goto end;

    EVP_PKEY_set1_DSA(pkey, dsa);

end:
    DSA_free(dsa);
    return pkey;
}

static EVP_PKEY *load_dsa_priv_key_params(void)
{
    return load_ffc_priv_key_params("DSA");
}
#endif /* !OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static EVP_PKEY *load_dh_priv_key_legacy()
{
    EVP_PKEY *pkey = NULL;
    DH *dh = NULL;

    pkey = EVP_PKEY_new();
    if (!TEST_ptr(pkey))
        goto end;

    dh = DH_new();
    if (!TEST_ptr(dh))
        goto end;

    if (!TEST_true(DH_set0_pqg(dh, td_get1_ffc_p_bn(), td_get1_ffc_q_bn(), td_get1_ffc_g_bn())))
        goto end;

    if (!TEST_true(DH_set0_key(dh, td_get1_ffc_priv_bn(), td_get1_ffc_pub_bn())))
        goto end;

    EVP_PKEY_set1_DH(pkey, dh);

end:
    DH_free(dh);
    return pkey;
}

static EVP_PKEY *load_dh_priv_key_params(void)
{
    return load_ffc_priv_key_params("DH");
}

static EVP_PKEY *gen_dh_named_priv_key_legacy(void)
{
    EVP_PKEY *pkey = NULL;
    DH *dh = NULL;

    pkey = EVP_PKEY_new();
    if (!TEST_ptr(pkey))
        goto end;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto end;

    if (!DH_generate_key(dh))
        goto end;

    EVP_PKEY_set1_DH(pkey, dh);

end:
    DH_free(dh);
    return pkey;
}

static EVP_PKEY *gen_dh_named_priv_key_params(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_int_gt(OSSL_PARAM_BLD_push_utf8_string(
                              bld, OSSL_PKEY_PARAM_GROUP_NAME,
                              "ffdhe2048", 0), 0))
        goto err;

    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          td_get0_ffc_pub_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             td_get0_ffc_priv_bn())))
        goto err;

    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(testctx, "DH", NULL))
        || !TEST_true(EVP_PKEY_fromdata_init(ctx))
        || !TEST_int_gt(EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params), 0))
        goto err;

err:
    OSSL_PARAM_BLD_free_params(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


#endif /* !OPENSSL_NO_DH */


static EVP_PKEY *load_rsa_priv_key_legacy(void)
{
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    pkey = EVP_PKEY_new();
    if (!TEST_ptr(pkey))
        goto end;

    rsa = RSA_new();
    if (!TEST_ptr(rsa))
        goto end;

    if (!TEST_true(RSA_set0_key(rsa, td_get1_rsa_n_bn(), td_get1_rsa_e_bn(), td_get1_rsa_d_bn())))
        goto end;

    if (!TEST_true(RSA_set0_factors(rsa, td_get1_rsa_p_bn(), td_get1_rsa_q_bn())))
        goto end;

    EVP_PKEY_set1_RSA(pkey, rsa);

end:
    RSA_free(rsa);
    return pkey;
}

static EVP_PKEY *load_rsa_priv_key_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)))
        goto err;

    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, td_get0_rsa_n_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, td_get0_rsa_e_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, td_get0_rsa_d_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, td_get0_rsa_p_bn()))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, td_get0_rsa_q_bn()))
        )
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params), 0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

err:
    OSSL_PARAM_BLD_free_params(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}


#ifndef OPENSSL_NO_DSA
static int test_pkey_DSA_get_params(EVP_PKEY *pkey)
{
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    int ret = 0;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                            &pub))
        || !TEST_BN_eq(td_get0_ffc_pub_bn(), pub)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                            &priv))
        || !TEST_BN_eq(td_get0_ffc_priv_bn(), priv)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        || !TEST_BN_eq(td_get0_ffc_p_bn(), p)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &q))
        || !TEST_BN_eq(td_get0_ffc_q_bn(), q)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &g))
        || !TEST_BN_eq(td_get0_ffc_g_bn(), g))
        goto err;

    ret = 1;
 err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}

static int test_pkey_DH_get_params(EVP_PKEY *pkey)
{
    return test_pkey_DSA_get_params(pkey);
}

static int test_pkey_DSA_get_legacy(EVP_PKEY *pkey)
{
    int ret = 0;
    const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    DSA *dsa = NULL;
/* Not supported for this key type
    unsigned char raw_priv[1000];
    unsigned char raw_pub[1000];
    size_t raw_priv_len = sizeof(raw_priv);
    size_t raw_pub_len = sizeof(raw_pub);
*/
    dsa = EVP_PKEY_get0_DSA(pkey);
    if (!TEST_ptr(dsa))
        goto err;
 
    DSA_get0_pqg(dsa, &p, &q, &g);
    if (!TEST_BN_eq(td_get0_ffc_p_bn(), p)
        || !TEST_BN_eq(td_get0_ffc_q_bn(), q)
        || !TEST_BN_eq(td_get0_ffc_g_bn(), g))
        goto err;

    DSA_get0_key(dsa, &pub, &priv);
    if (!TEST_BN_eq(td_get0_ffc_pub_bn(), pub)
        || !TEST_BN_eq(td_get0_ffc_priv_bn(), priv))
        goto err;

/* Not supported for this key type
    if (!TEST_true(EVP_PKEY_get_raw_private_key(pkey, raw_priv, &raw_priv_len))
        || !TEST_mem_eq(ffc_priv, sizeof(ffc_priv), raw_priv, raw_priv_len))
        goto err;

    if (!TEST_true(EVP_PKEY_get_raw_public_key(pkey, raw_pub, &raw_pub_len))
        || !TEST_mem_eq(ffc_pub, sizeof(ffc_pub), raw_pub, raw_pub_len))
        goto err;
*/

    ret = 1;
err:
    return ret;
}

static int test_pkey_DSA_legacy(void)
{
    int ret = 0;

    EVP_PKEY *pkey = load_dsa_priv_key_legacy();
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_true(test_pkey_DSA_get_params(pkey))
        || !TEST_true(test_pkey_DSA_get_legacy(pkey)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_pkey_DSA_params(void)
{
    int ret = 0;

    EVP_PKEY *pkey = load_dsa_priv_key_params();
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_true(test_pkey_DSA_get_params(pkey))
        || !TEST_true(test_pkey_DSA_get_legacy(pkey)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}
#endif /* !OPENSSL_NO_DSA */


static int test_pkey_RSA_get_params(EVP_PKEY *pkey)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    int ret = 0;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n))
        || !TEST_BN_eq(td_get0_rsa_n_bn(), n)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e))
        || !TEST_BN_eq(td_get0_rsa_e_bn(), e)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d))
        || !TEST_BN_eq(td_get0_rsa_d_bn(), d)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p))
        || !TEST_BN_eq(td_get0_rsa_p_bn(), p)
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q))
        || !TEST_BN_eq(td_get0_rsa_q_bn(), q)
        )
        goto err;

    ret = 1;

 err:
    EVP_PKEY_free(pkey);
    OSSL_PARAM_BLD_free_params(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}

static int test_pkey_RSA_get_legacy(EVP_PKEY *pkey)
{
    int ret = 0;
    const BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    RSA *rsa = NULL;

    rsa = EVP_PKEY_get0_RSA(pkey);
    if (!TEST_ptr(rsa))
        goto err;

    RSA_get0_key(rsa, &n, &e, &d);
    if (!TEST_BN_eq(td_get0_rsa_n_bn(), n)
        || !TEST_BN_eq(td_get0_rsa_e_bn(), e)
        || !TEST_BN_eq(td_get0_rsa_d_bn(), d))
        goto err;

    RSA_get0_factors(rsa, &p, &q);
    if (!TEST_BN_eq(td_get0_rsa_p_bn(), p)
        || !TEST_BN_eq(td_get0_rsa_q_bn(), q))
        goto err;

    ret = 1;
err:
    return ret;
}

static int test_pkey_RSA_legacy(void)
{
    EVP_PKEY *pkey = load_rsa_priv_key_legacy();
    if (!TEST_ptr(pkey))
        return 0;

    return test_pkey_RSA_get_params(pkey) && test_pkey_RSA_get_legacy(pkey);
}

static int test_pkey_RSA_params(void)
{
    EVP_PKEY *pkey = load_rsa_priv_key_params();
    if (!TEST_ptr(pkey))
        return 0;

    return test_pkey_RSA_get_params(pkey) && test_pkey_RSA_get_legacy(pkey);
}

#ifndef OPENSSL_NO_DH
static int test_pkey_DH_get_legacy(EVP_PKEY *pkey)
{
    int ret = 0;
    const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    DH *dh = NULL;

    dh = EVP_PKEY_get0_DH(pkey);
    if (!TEST_ptr(dh))
        goto err;

    DH_get0_pqg(dh, &p, &q, &g);
    if (!TEST_BN_eq(td_get0_ffc_p_bn(), p)
        || !TEST_BN_eq(td_get0_ffc_q_bn(), q)
        || !TEST_BN_eq(td_get0_ffc_g_bn(), g))
        goto err;

    DH_get0_key(dh, &pub, &priv);
    if (!TEST_BN_eq(td_get0_ffc_pub_bn(), pub)
        || !TEST_BN_eq(td_get0_ffc_priv_bn(), priv))
        goto err;

    char name[80];
    size_t len;
    if (!TEST_true(EVP_PKEY_get_group_name(pkey, name, sizeof(name), &len)))
        goto err;

    ret = 1;
err:
    return ret;
}

static int test_pkey_legacy_DH_named_get_group_name(void)
{
    int ret = 0;
    char name1[80];
    char name2[80];
    size_t len1;
    size_t len2;
    EVP_PKEY *pkey = NULL;

    /* Test with a legacy pkey */
    pkey = gen_dh_named_priv_key_legacy();
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_true(EVP_PKEY_get_group_name(pkey, name1, sizeof(name1), &len1))
        || !TEST_str_eq("ffdhe2048", name1))
        goto err;

    if (!TEST_true(EVP_PKEY_get_utf8_string_param(pkey,
                                                   OSSL_PKEY_PARAM_GROUP_NAME,
                                                   name2,
                                                   sizeof(name2), &len2))
        || !TEST_str_eq("ffdhe2048", name2))
        goto err;
 
    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_pkey_params_DH_named_get_group_name(void)
{
    int ret = 0;
    char name1[80];
    char name2[80];
    size_t len1;
    size_t len2;
    EVP_PKEY *pkey = NULL;

    pkey = gen_dh_named_priv_key_params();
    if (!TEST_ptr(pkey))
        goto err;

    if (!TEST_true(EVP_PKEY_get_group_name(pkey, name1, sizeof(name1), &len1))
        || !TEST_str_eq("ffdhe2048", name1))
        goto err;

    if (!TEST_true(EVP_PKEY_get_utf8_string_param(pkey,
                                                   OSSL_PKEY_PARAM_GROUP_NAME,
                                                   name2,
                                                   sizeof(name2), &len2))
        || !TEST_str_eq("ffdhe2048", name2))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_pkey_ctx_DH_get_legacy(EVP_PKEY *pkey)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, NULL);
    if (!TEST_ptr(ctx))
        goto err;

    // Todo: test stuff
    
    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_pkey_ctx_DH_get_params(EVP_PKEY *pkey)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(testctx, pkey, NULL);
    if (!TEST_ptr(ctx))
        goto err;

    // Todo: test stuff

    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_pkey_DH_legacy(void)
{
    int ret = 0;

    EVP_PKEY *pkey = load_dh_priv_key_legacy();
    if (!TEST_ptr(pkey))
        goto err;

    /* Read data from the EVP_PKEY */
    if (!TEST_true(test_pkey_DH_get_params(pkey))
        || !TEST_true(test_pkey_DH_get_legacy(pkey)))
        goto err;

    /* Read data from a EVP_PKEY_CTX based on the pkey */
    if (!TEST_true(test_pkey_ctx_DH_get_params(pkey)) 
        || !TEST_true(test_pkey_ctx_DH_get_legacy(pkey)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_pkey_DH_params(void)
{
    int ret = 0;

    EVP_PKEY *pkey = load_dh_priv_key_params();
    if (!TEST_ptr(pkey))
        goto err;

    /* Read data from the EVP_PKEY */
    if (!TEST_true(test_pkey_DH_get_params(pkey)) 
        || !TEST_true(test_pkey_DH_get_legacy(pkey)))
        goto err;

    /* Read data from a EVP_PKEY_CTX based on the pkey */
    if (!TEST_true(test_pkey_ctx_DH_get_params(pkey)) 
        || !TEST_true(test_pkey_ctx_DH_get_legacy(pkey)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    return ret;
}

#endif /* !OPENSSL_NO_DH */


int setup_tests(void)
{
    testctx = OSSL_LIB_CTX_new();

    if (!TEST_ptr(testctx))
        return 0;

#ifndef OPENSSL_NO_DSA
    ADD_TEST(test_pkey_DSA_legacy);
    ADD_TEST(test_pkey_DSA_params);
#endif
    ADD_TEST(test_pkey_RSA_legacy);
    ADD_TEST(test_pkey_RSA_params);
#ifndef OPENSSL_NO_DH
    ADD_TEST(test_pkey_DH_legacy);
    ADD_TEST(test_pkey_DH_params);
    ADD_TEST(test_pkey_legacy_DH_named_get_group_name);
    ADD_TEST(test_pkey_params_DH_named_get_group_name);
#endif
    return 1;
}

void cleanup_tests(void)
{
    td_free();

    OSSL_LIB_CTX_free(testctx);
}
