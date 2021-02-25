/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/trace.h>
#include <openssl/core_names.h>
#include "crypto/evp.h"
#include "evp_local.h"

int PKCS5_v2_PBKDF2_encode(X509_ALGOR **algor, OSSL_PARAM *params);

int pkcs5_pbkdf2_hmac_ex(const char *pass, int passlen,
                         const unsigned char *salt, int saltlen, int iter,
                         const EVP_MD *digest, int keylen, unsigned char *out,
                         OSSL_LIB_CTX *libctx, const char *propq)
{
    const char *empty = "";
    int rv = 1, mode = 1;
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    const char *mdname = EVP_MD_name(digest);
    OSSL_PARAM params[6], *p = params;

    /* Keep documented behaviour. */
    if (pass == NULL) {
        pass = empty;
        passlen = 0;
    } else if (passlen == -1) {
        passlen = strlen(pass);
    }
    if (salt == NULL && saltlen == 0)
        salt = (unsigned char *)empty;

    kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF2, propq);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL)
        return 0;
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                             (char *)pass, (size_t)passlen);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             (unsigned char *)salt, saltlen);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iter);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)mdname, 0);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, keylen, params) != 1)
        rv = 0;

    EVP_KDF_CTX_free(kctx);

    OSSL_TRACE_BEGIN(PKCS5V2) {
        BIO_printf(trc_out, "Password:\n");
        BIO_hex_string(trc_out,
                       0, passlen, pass, passlen);
        BIO_printf(trc_out, "\n");
        BIO_printf(trc_out, "Salt:\n");
        BIO_hex_string(trc_out,
                       0, saltlen, salt, saltlen);
        BIO_printf(trc_out, "\n");
        BIO_printf(trc_out, "Iteration count %d\n", iter);
        BIO_printf(trc_out, "Key:\n");
        BIO_hex_string(trc_out,
                       0, keylen, out, keylen);
        BIO_printf(trc_out, "\n");
    } OSSL_TRACE_END(PKCS5V2);
    return rv;
}

int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt,
                      int saltlen, int iter, const EVP_MD *digest, int keylen,
                      unsigned char *out)
{
    return pkcs5_pbkdf2_hmac_ex(pass, passlen, salt, saltlen, iter, digest,
                                keylen, out, NULL, NULL);
}


int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out)
{
    return PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, EVP_sha1(),
                             keylen, out);
}

/*
 * Now the key derivation function itself. This is a bit evil because it has
 * to check the ASN1 parameters are valid: and there are quite a few of
 * them...
 */

int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          ASN1_TYPE *param, const EVP_CIPHER *c,
                          const EVP_MD *md, int en_de)
{
    PBE2PARAM *pbe2 = NULL;
    const EVP_CIPHER *cipher;
    EVP_PBE_KEYGEN *kdf;

    int rv = 0;

    pbe2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), param);
    if (pbe2 == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto err;
    }

    /* See if we recognise the key derivation function */
    if (!EVP_PBE_find(EVP_PBE_TYPE_KDF, OBJ_obj2nid(pbe2->keyfunc->algorithm),
                        NULL, NULL, &kdf)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
        goto err;
    }

    /*
     * lets see if we recognise the encryption algorithm.
     */

    cipher = EVP_get_cipherbyobj(pbe2->encryption->algorithm);

    if (!cipher) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER);
        goto err;
    }

    /* Fixup cipher based on AlgorithmIdentifier */
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, en_de))
        goto err;
    if (EVP_CIPHER_asn1_to_param(ctx, pbe2->encryption->parameter) < 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR);
        goto err;
    }
    rv = kdf(ctx, pass, passlen, pbe2->keyfunc->parameter, NULL, NULL, en_de);
 err:
    PBE2PARAM_free(pbe2);
    return rv;
}

int PKCS5_PBE2_keygen_ex(EVP_CIPHER_CTX **ctx, OSSL_PARAM *params, 
                        const char *pass, int passlen, int en_de, 
                        OSSL_LIB_CTX *libctx, const char *propq)
{
    return 0;
}

int PKCS5_PBE2_encode(X509_ALGOR **algor, OSSL_PARAM params[], OSSL_LIB_CTX *libctx, char *propq)
{
    const OSSL_PARAM *p;
    X509_ALGOR *scheme = NULL, *ret = NULL;
    //int keylen;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    PBE2PARAM *pbe2 = NULL;
    unsigned char *aiv = NULL;
    size_t aiv_len;

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p == NULL)
        goto merr;
    if (p->data_type != OSSL_PARAM_UTF8_STRING)
        goto merr;

    cipher = EVP_CIPHER_fetch(libctx, p->data, propq);
    if (cipher == NULL)
        goto merr;

    if ((pbe2 = PBE2PARAM_new()) == NULL)
        goto merr;

    /* Setup the AlgorithmIdentifier for the encryption scheme */
    scheme = pbe2->encryption;
    scheme->algorithm = OBJ_nid2obj(EVP_CIPHER_type(cipher));
    if ((scheme->parameter = ASN1_TYPE_new()) == NULL)
        goto merr;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IV);
    if (p == NULL)
        goto merr;
    if (!OSSL_PARAM_get_octet_string(p, (void**)&aiv, 0, &aiv_len))
        goto merr;

    if (EVP_CIPHER_iv_length(cipher)) {
        if (aiv)
            memcpy(iv, aiv, EVP_CIPHER_iv_length(cipher));
        /* Create random IV if none given */
        else if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) <= 0)
            goto err;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto merr;

    /* Dummy cipherinit to just setup the IV, and PRF */
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, iv, 0))
        goto err;
    if (EVP_CIPHER_param_to_asn1(ctx, scheme->parameter) <= 0) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ERROR_SETTING_CIPHER_PARAMS);
        goto err;
    }
    /*
     * If prf NID unspecified see if cipher has a preference. An error is OK
     * here: just means use default PRF.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PRF);
    int prf_nid = OBJ_txt2nid(p->data);
    if ((prf_nid == -1) &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_PBE_PRF_NID, 0, &prf_nid) <= 0) {
        ERR_clear_error();
        prf_nid = NID_hmacWithSHA256;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* If its RC2 then we'd better setup the key length */
// TODO: Put back in
//    if (EVP_CIPHER_type(cipher) == NID_rc2_cbc)
//        keylen = EVP_CIPHER_key_length(cipher);
//    else
//        keylen = -1;

    /* Setup keyfunc */

    X509_ALGOR_free(pbe2->keyfunc);

    if (!PKCS5_v2_PBKDF2_encode(&pbe2->keyfunc, params))
        goto merr;

    /* Now set up top level AlgorithmIdentifier */
    if ((*algor = X509_ALGOR_new()) == NULL)
        goto merr;

    (*algor)->algorithm = OBJ_nid2obj(NID_pbes2);

    /* Encode PBE2PARAM into parameter */
    if (!ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBE2PARAM), pbe2,
                                 &((*algor)->parameter)))
         goto merr;

    PBE2PARAM_free(pbe2);
    pbe2 = NULL;

    return 1;

 merr:
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);

 err:
    EVP_CIPHER_CTX_free(ctx);
    PBE2PARAM_free(pbe2);
    /* Note 'scheme' is freed as part of pbe2 */
    X509_ALGOR_free(*algor);

    return 0;
}

int PKCS5_PBE2_decode(X509_ALGOR *algor, OSSL_PARAM **params)
{
    PBE2PARAM *pbe2 = NULL;
    EVP_PBE_METH *kdf_meth;
    char cipher_name[80];
    int rv = 0;
    OSSL_PARAM *p;

    *params = p = OPENSSL_malloc(sizeof(OSSL_PARAM) * 8);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PBE_PARAM_ALG, "PBES2", 0);

    pbe2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), algor->parameter);
    if (pbe2 == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto err;
    }

    /* See if we recognise the key derivation function */
    if (!EVP_PBE_find_ex(EVP_PBE_TYPE_KDF, OBJ_obj2nid(pbe2->keyfunc->algorithm),
                         NULL, NULL, NULL, &kdf_meth)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
        goto err;
    }

    /* Lets see if we recognise the encryption algorithm. */
    OBJ_obj2txt(cipher_name, sizeof(cipher_name), pbe2->encryption->algorithm, 0);
    if (cipher_name == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER);
        goto err;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PBE_PARAM_CIPHER, cipher_name, 0);

    /* Stolen from EVP_CIPHER_get_asn1_iv. For PBES2 the AI contains only the IV */
    if (pbe2->encryption->parameter != NULL) {
        unsigned char iv[EVP_MAX_IV_LENGTH];
        int iv_len;

        iv_len = ASN1_TYPE_get_octetstring(pbe2->encryption->parameter, iv, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PBE_PARAM_CIPHER, iv, iv_len);
    }
    *p++ = OSSL_PARAM_construct_end();

    /* Fixup cipher based on AlgorithmIdentifier */
/*    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, en_de))
        goto err;
    if (EVP_CIPHER_asn1_to_param(ctx, pbe2->encryption->parameter) < 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_CIPHER_PARAMETER_ERROR);
        goto err;
    }
*/
    rv = kdf_meth->decode(pbe2->keyfunc, params);
 err:
    PBE2PARAM_free(pbe2);
    return rv;
}

const EVP_PBE_METH PKCS5_PBE2_METH = {
    OSSL_PBE_NAME_PBES2, PKCS5_PBE2_keygen_ex, PKCS5_PBE2_encode, PKCS5_PBE2_decode
};

int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, ASN1_TYPE *param,
                             const EVP_CIPHER *c, const EVP_MD *md, int en_de)
{
    unsigned char *salt, key[EVP_MAX_KEY_LENGTH];
    int saltlen, iter, t;
    int rv = 0;
    unsigned int keylen = 0;
    int prf_nid, hmac_md_nid;
    PBKDF2PARAM *kdf = NULL;
    const EVP_MD *prfmd;

    if (EVP_CIPHER_CTX_cipher(ctx) == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        goto err;
    }
    keylen = EVP_CIPHER_CTX_key_length(ctx);
    OPENSSL_assert(keylen <= sizeof(key));

    /* Decode parameter */

    kdf = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), param);

    if (kdf == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto err;
    }

    t = EVP_CIPHER_CTX_key_length(ctx);
    if (t < 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH);
        goto err;
    }
    keylen = t;

    /* Now check the parameters of the kdf */

    if (kdf->keylength && (ASN1_INTEGER_get(kdf->keylength) != (int)keylen)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEYLENGTH);
        goto err;
    }

    if (kdf->prf)
        prf_nid = OBJ_obj2nid(kdf->prf->algorithm);
    else
        prf_nid = NID_hmacWithSHA1;

    if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, prf_nid, NULL, &hmac_md_nid, 0)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    prfmd = EVP_get_digestbynid(hmac_md_nid);
    if (prfmd == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    if (kdf->salt->type != V_ASN1_OCTET_STRING) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_SALT_TYPE);
        goto err;
    }

    /* it seems that its all OK */
    salt = kdf->salt->value.octet_string->data;
    saltlen = kdf->salt->value.octet_string->length;
    iter = ASN1_INTEGER_get(kdf->iter);
    if (!PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, prfmd,
                           keylen, key))
        goto err;
    rv = EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, en_de);
 err:
    OPENSSL_cleanse(key, keylen);
    PBKDF2PARAM_free(kdf);
    return rv;
}

int PKCS5_v2_PBKDF2_keygen_ex(EVP_CIPHER_CTX **ctx, OSSL_PARAM *params,
                        const char *pass, int passlen, int en_de,
                        OSSL_LIB_CTX *libctx, const char *propq)
{
    return 0;
}

int PKCS5_v2_PBKDF2_encode(X509_ALGOR **algor, OSSL_PARAM *params)
{
    return 0;
}

int PKCS5_v2_PBKDF2_decode(X509_ALGOR *algor, OSSL_PARAM **params)
{
    unsigned char *salt;
    int saltlen;
    unsigned int iter;
    int rv = 0;
    unsigned int keylen = 0;
    int prf_nid, hmac_md_nid;
    char *prf_name;
    char *md_name;
    PBKDF2PARAM *kdf = NULL;
    OSSL_PARAM *p;

    *params = p = OPENSSL_malloc(sizeof(OSSL_PARAM) * 8);;

    /* Decode parameter */
    kdf = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), algor->parameter);
    if (kdf == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto err;
    }

    if (kdf->prf)
        prf_nid = OBJ_obj2nid(kdf->prf->algorithm);
    else
        prf_nid = NID_hmacWithSHA1;

    if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, prf_nid, NULL, &hmac_md_nid, 0)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    prf_name = OBJ_nid2sn(prf_nid);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PRF, prf_name, 0);
 
    md_name = OBJ_nid2sn(hmac_md_nid);
    if (md_name == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);

    if (kdf->salt->type != V_ASN1_OCTET_STRING) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_SALT_TYPE);
        goto err;
    }
    salt = kdf->salt->value.octet_string->data;
    saltlen = kdf->salt->value.octet_string->length;
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, saltlen);

    iter = ASN1_INTEGER_get(kdf->iter);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);

    rv = 1;
err:
    PBKDF2PARAM_free(kdf);
    return rv;
}

const EVP_PBE_METH PKCS5_PBKDF2_METH = {
    OSSL_KDF_NAME_PBKDF2, PKCS5_v2_PBKDF2_keygen_ex, PKCS5_v2_PBKDF2_encode, PKCS5_v2_PBKDF2_decode
};

