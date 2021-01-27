/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file contains general test data for use in compiled tests
 */


#define BN_GETTER_DECL(param)         \
BIGNUM *td_get0_##param##_bn(void);   \
BIGNUM *td_get1_##param##_bn(void);   \
extern const size_t td_##param##_size

/* Free all test data obtained using td_get0_xxx() */
void td_free(void);


/* FFC (DH, DSA) Test Data */

/*
 * seed, p, q, g are taken from the updated Appendix 5 to FIPS
 * PUB 186 and also appear in Appendix 5 to FIPS PIB 186-1
 */
extern const unsigned char td_ffc_seed[];
extern const unsigned char td_ffc_p[];
extern const unsigned char td_ffc_q[];
extern const unsigned char td_ffc_g[];
extern const unsigned char td_ffc_priv[];
extern const unsigned char td_ffc_pub[];

BN_GETTER_DECL(ffc_p);
BN_GETTER_DECL(ffc_q);
BN_GETTER_DECL(ffc_g);
BN_GETTER_DECL(ffc_seed);
BN_GETTER_DECL(ffc_priv);
BN_GETTER_DECL(ffc_pub);


/* DSA Test Data */

extern const unsigned char td_dsa_seed[];
extern const unsigned char td_dsa_p[];
extern const unsigned char td_dsa_q[];
extern const unsigned char td_dsa_g[];
extern const unsigned char td_dsa_priv[];
extern const unsigned char td_dsa_pub[];
extern const int td_dsa_gindex;
extern const int td_dsa_pcounter;

BN_GETTER_DECL(dsa_p);
BN_GETTER_DECL(dsa_q);
BN_GETTER_DECL(dsa_g);
BN_GETTER_DECL(dsa_seed);
BN_GETTER_DECL(dsa_priv);
BN_GETTER_DECL(dsa_pub);


/* RSA Test Data */

extern const unsigned char td_rsa_n[];
extern const unsigned char td_rsa_e[];
extern const unsigned char td_rsa_d[];
extern const unsigned char td_rsa_p[];
extern const unsigned char td_rsa_q[];

BN_GETTER_DECL(rsa_n);
BN_GETTER_DECL(rsa_e);
BN_GETTER_DECL(rsa_d);
BN_GETTER_DECL(rsa_p);
BN_GETTER_DECL(rsa_q);


/* DH Test Data */

extern const unsigned char td_dh_priv[];
extern const unsigned char td_dh_pub[];
extern const char td_dh_group_name[];
extern const long td_dh_priv_len;

BN_GETTER_DECL(dh_priv);
BN_GETTER_DECL(dh_pub);


/* EC Test Data */

extern const char *td_ec_p256_curve;
extern const unsigned char td_ec_p256_priv[];
extern const unsigned char td_ec_p256_pub[];

BN_GETTER_DECL(ec_p256_priv);
BN_GETTER_DECL(ec_p256_pub);
