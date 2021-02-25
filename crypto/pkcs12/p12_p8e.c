/*
 * Copyright 2001-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/core.h>
#include <openssl/pkcs12.h>
#include "crypto/x509.h"

/*
 * TODO: Params must include:
 * - PBE ID
 * - Cipher ID (Optional based on PBE type)
 * - Password
 * - IV (Optional)
 * - Iterations
 *
 */
X509_SIG *PKCS8_encrypt_ex(PKCS8_PRIV_KEY_INFO *p8inf, OSSL_PARAM params[],
                           const char *pass, int passlen,
                           OSSL_LIB_CTX *ctx, const char *propq)
{
    X509_ALGOR *pbe;
    X509_SIG *p8 = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    unsigned char *in = NULL;
    int inlen;

    /* Encode the PKCS8 blob */
    if ((oct = ASN1_OCTET_STRING_new()) == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    inlen = ASN1_item_i2d((void*)p8inf, &in, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO));
    if (!in) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCODE_ERROR);
        goto err;
    }

    /* Do the encrypt */
    if (!PKCS12_pbe_crypt_ex(params, pass, passlen, in, inlen, &oct->data, &oct->length,
                             1, ctx, propq))
        return NULL;

    /* Encode the used parameters */
    EVP_PBE_params_to_asn1(&pbe, params);
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB);
        return NULL;
    }

    p8 = OPENSSL_zalloc(sizeof(*p8));
    p8->algor = pbe;
    p8->digest = oct;
    return p8;
err:
    /* TODO: Clean up */
    return NULL;
}


X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher,
                        const char *pass, int passlen,
                        unsigned char *salt, int saltlen, int iter,
                        PKCS8_PRIV_KEY_INFO *p8inf)
{
    X509_SIG *p8 = NULL;
    X509_ALGOR *pbe;

    if (pbe_nid == -1)
        pbe = PKCS5_pbe2_set(cipher, iter, salt, saltlen);
    else if (EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, NULL, NULL, 0))
        pbe = PKCS5_pbe2_set_iv(cipher, iter, salt, saltlen, NULL, pbe_nid);
    else {
        ERR_clear_error();
        pbe = PKCS5_pbe_set(pbe_nid, iter, salt, saltlen);
    }
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB);
        return NULL;
    }
    p8 = PKCS8_set0_pbe(pass, passlen, p8inf, pbe);
    if (p8 == NULL) {
        X509_ALGOR_free(pbe);
        return NULL;
    }

    return p8;
}

X509_SIG *PKCS8_set0_pbe(const char *pass, int passlen,
                         PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe)
{
    X509_SIG *p8;
    ASN1_OCTET_STRING *enckey;

    enckey =
        PKCS12_item_i2d_encrypt(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO),
                                pass, passlen, p8inf, 1);
    if (!enckey) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_ENCRYPT_ERROR);
        return NULL;
    }

    p8 = OPENSSL_zalloc(sizeof(*p8));

    if (p8 == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        ASN1_OCTET_STRING_free(enckey);
        return NULL;
    }
    p8->algor = pbe;
    p8->digest = enckey;

    return p8;
}
