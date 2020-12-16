/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#if !defined(OPENSSL_NO_ENGINE)
#include <openssl/engine.h>
#endif /* if !defined(OPENSSL_NO_ENGINE) */

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include <dst/result.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

#if HAVE_OPENSSL_ED25519
#ifndef NID_ED25519
#error "Ed25519 group is not known (NID_ED25519)"
#endif /* ifndef NID_ED25519 */
#endif /* HAVE_OPENSSL_ED25519 */

#if HAVE_OPENSSL_ED448
#ifndef NID_ED448
#error "Ed448 group is not known (NID_ED448)"
#endif /* ifndef NID_ED448 */
#endif /* HAVE_OPENSSL_ED448 */

#ifndef NID_X9_62_prime256v1
#error "P-256 group is not known (NID_X9_62_prime256v1)"
#endif /* ifndef NID_X9_62_prime256v1 */
#ifndef NID_secp384r1
#error "P-384 group is not known (NID_secp384r1)"
#endif /* ifndef NID_secp384r1 */

static bool
opensslec_isprivate(const dst_key_t *key);

static isc_result_t
opensslec_fromlabel(dst_key_t *key, const char *engine, const char *label,
		    const char *pin);

#if !HAVE_ECDSA_SIG_GET0
/* From OpenSSL 1.1 */
static void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
	if (pr != NULL) {
		*pr = sig->r;
	}
	if (ps != NULL) {
		*ps = sig->s;
	}
}

static int
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
	if (r == NULL || s == NULL) {
		return (0);
	}

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;

	return (1);
}
#endif /* !HAVE_ECDSA_SIG_GET0 */

static isc_result_t
key_check(const dst_key_t *key, int *baseid, int *nid, size_t *keysize,
	  size_t *sigsize) {
	int id = EVP_PKEY_NONE;
	int nidv = 0;
	int klen = 0;
	int slen = 0;

	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_ECDSA256 ||
		key->key_alg == DST_ALG_ECDSA384 ||
		key->key_alg == DST_ALG_ED25519 ||
		key->key_alg == DST_ALG_ED448);

	if (key->key_alg == DST_ALG_ECDSA256) {
		id = EVP_PKEY_EC;
		nidv = NID_X9_62_prime256v1;
		klen = DNS_KEY_ECDSA256SIZE;
		slen = DNS_SIG_ECDSA256SIZE;
	}
	if (key->key_alg == DST_ALG_ECDSA384) {
		id = EVP_PKEY_EC;
		nidv = NID_secp384r1;
		klen = DNS_KEY_ECDSA384SIZE;
		slen = DNS_SIG_ECDSA384SIZE;
	}
#if HAVE_OPENSSL_ED25519
	if (key->key_alg == DST_ALG_ED25519) {
		id = EVP_PKEY_ED25519;
		nidv = NID_ED25519;
		klen = DNS_KEY_ED25519SIZE;
		slen = DNS_SIG_ED25519SIZE;
	}
#endif /* if HAVE_OPENSSL_ED25519 */
#if HAVE_OPENSSL_ED448
	if (key->key_alg == DST_ALG_ED448) {
		id = EVP_PKEY_ED448;
		nidv = NID_ED448;
		klen = DNS_KEY_ED448SIZE;
		slen = DNS_SIG_ED448SIZE;
	}
#endif /* if HAVE_OPENSSL_ED448 */

	if (id == EVP_PKEY_NONE) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	if (baseid != NULL) {
		*baseid = id;
	}
	if (nid != NULL) {
		*nid = nidv;
	}
	if (keysize != NULL) {
		*keysize = klen;
	}
	if (sigsize != NULL) {
		*sigsize = slen;
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
ec_check(EVP_PKEY *pkey, EVP_PKEY *pubpkey) {
	if (pubpkey == NULL) {
		return (ISC_R_SUCCESS);
	}
	if (EVP_PKEY_cmp(pkey, pubpkey) == 1) {
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_FAILURE);
}

static isc_result_t
key2ossl(dst_key_t *dkey, bool isprivate, const unsigned char *key,
	 size_t *key_len, EVP_PKEY **pkey) {
	isc_result_t ret;
	int pkey_type = EVP_PKEY_NONE;
	int nid = 0;
	size_t len = 0;
	EC_KEY *eckey = NULL;

	ret = key_check(dkey, &pkey_type, &nid, &len, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	if ((pkey_type != EVP_PKEY_EC) && (*key_len < len)) {
		return (isprivate ? DST_R_INVALIDPRIVATEKEY
				  : DST_R_INVALIDPUBLICKEY);
	}

	if (isprivate) {
		BIGNUM *privkey;

		switch (pkey_type) {
		case EVP_PKEY_EC:
			/* Should we use this API instead?
			 * EC_KEY *d2i_ECPrivateKey(EC_KEY **key, const unsigned
			 * char **in, long len); int i2d_ECPrivateKey(EC_KEY
			 * *key, unsigned char **out);
			 */
			privkey = BN_bin2bn(key, *key_len, NULL);
			eckey = EC_KEY_new_by_curve_name(nid);
			if (eckey == NULL) {
				return (dst__openssl_toresult(
					DST_R_OPENSSLFAILURE));
			}
			if (EC_KEY_set_private_key(eckey, privkey) == 0) {
				BN_clear_free(privkey);
				DST_RET(dst__openssl_toresult(
					DST_R_INVALIDPRIVATEKEY));
			}
			BN_clear_free(privkey);
			break;
#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
#if HAVE_OPENSSL_ED25519
		case EVP_PKEY_ED25519:
#endif /* HAVE_OPENSSL_ED25519 */
#if HAVE_OPENSSL_ED448
		case EVP_PKEY_ED448:
#endif /* HAVE_OPENSSL_ED448 */
			*pkey = EVP_PKEY_new_raw_private_key(pkey_type, NULL,
							     key, len);
			break;
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
		default:
			DST_RET(ISC_R_FAILURE);
		}
	} else {
		const unsigned char *cp;
		unsigned char buf[DNS_KEY_ECDSA384SIZE + 1];

		switch (pkey_type) {
		case EVP_PKEY_EC:
			eckey = EC_KEY_new_by_curve_name(nid);
			if (eckey == NULL) {
				return (dst__openssl_toresult(
					DST_R_OPENSSLFAILURE));
			}
			buf[0] = POINT_CONVERSION_UNCOMPRESSED;
			memmove(buf + 1, key, len);
			cp = buf;
			if (o2i_ECPublicKey(&eckey, (const unsigned char **)&cp,
					    (long)len + 1) == NULL) {
				DST_RET(dst__openssl_toresult(
					DST_R_INVALIDPUBLICKEY));
			}
			break;
#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
#if HAVE_OPENSSL_ED25519
		case EVP_PKEY_ED25519:
#endif /* HAVE_OPENSSL_ED25519 */
#if HAVE_OPENSSL_ED448
		case EVP_PKEY_ED448:
#endif /* HAVE_OPENSSL_ED448 */
			*pkey = EVP_PKEY_new_raw_public_key(pkey_type, NULL,
							    key, len);
			break;
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
		default:
			DST_RET(ISC_R_FAILURE);
		}
	}

	if (pkey_type == EVP_PKEY_EC) {
		*pkey = EVP_PKEY_new();
	}

	if (*pkey == NULL) {
		DST_RET(dst__openssl_toresult(ISC_R_NOMEMORY));
	}

	if (pkey_type == EVP_PKEY_EC) {
		if (!EVP_PKEY_set1_EC_KEY(*pkey, eckey)) {
			EVP_PKEY_free(*pkey);
			*pkey = NULL;
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		}
	}

	*key_len = len;
	ret = ISC_R_SUCCESS;

err:
	if (eckey != NULL) {
		EC_KEY_free(eckey);
	}
	return (ret);
}

static int
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);

	while (bytes-- > 0) {
		*buf++ = 0;
	}
	BN_bn2bin(bn, buf);
	return (size);
}

static isc_result_t
ecdsa_sign(dst_context_t *dctx, isc_buffer_t *sig, isc_region_t *sigreg,
	   size_t siglen, EVP_PKEY *pkey) {
	isc_result_t ret;
	ECDSA_SIG *ecdsasig;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	const BIGNUM *r, *s;

	if (!EVP_DigestFinal(evp_md_ctx, digest, &dgstlen)) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestFinal", ISC_R_FAILURE));
	}

	ecdsasig = ECDSA_do_sign(digest, dgstlen, eckey);
	if (ecdsasig == NULL) {
		DST_RET(dst__openssl_toresult3(dctx->category, "ECDSA_do_sign",
					       DST_R_SIGNFAILURE));
	}
	ECDSA_SIG_get0(ecdsasig, &r, &s);
	BN_bn2bin_fixed(r, sigreg->base, siglen / 2);
	isc_region_consume(sigreg, siglen / 2);
	BN_bn2bin_fixed(s, sigreg->base, siglen / 2);
	isc_region_consume(sigreg, siglen / 2);
	ECDSA_SIG_free(ecdsasig);
	isc_buffer_add(sig, siglen);
	ret = ISC_R_SUCCESS;

err:
	EC_KEY_free(eckey);
	return (ret);
}

static isc_result_t
ecdsa_verify(dst_context_t *dctx, const isc_region_t *sig, EVP_PKEY *pkey) {
	isc_result_t ret;
	int status;
	unsigned char *cp = sig->base;
	ECDSA_SIG *ecdsasig = NULL;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);
	unsigned int dgstlen;
	unsigned char digest[EVP_MAX_MD_SIZE];
	BIGNUM *r = NULL, *s = NULL;

	if (!EVP_DigestFinal_ex(evp_md_ctx, digest, &dgstlen)) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestFinal_ex", ISC_R_FAILURE));
	}

	ecdsasig = ECDSA_SIG_new();
	if (ecdsasig == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	r = BN_bin2bn(cp, sig->length / 2, NULL);
	cp += sig->length / 2;
	s = BN_bin2bn(cp, sig->length / 2, NULL);
	ECDSA_SIG_set0(ecdsasig, r, s);
	/* cp += sig->len / 2; */

	status = ECDSA_do_verify(digest, dgstlen, ecdsasig, eckey);
	switch (status) {
	case 1:
		ret = ISC_R_SUCCESS;
		break;
	case 0:
		ret = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		ret = dst__openssl_toresult3(dctx->category, "ECDSA_do_verify",
					     DST_R_VERIFYFAILURE);
		break;
	}

err:
	if (ecdsasig != NULL) {
		ECDSA_SIG_free(ecdsasig);
	}
	EC_KEY_free(eckey);
	return (ret);
}

static bool
ecdsa_compare(EVP_PKEY *pkey1, EVP_PKEY *pkey2) {
	bool ret;
	EC_KEY *eckey1 = NULL;
	EC_KEY *eckey2 = NULL;
	const BIGNUM *priv1, *priv2;

	eckey1 = EVP_PKEY_get1_EC_KEY(pkey1);
	eckey2 = EVP_PKEY_get1_EC_KEY(pkey2);
	if (eckey1 == NULL && eckey2 == NULL) {
		DST_RET(true);
	} else if (eckey1 == NULL || eckey2 == NULL) {
		DST_RET(false);
	}

	priv1 = EC_KEY_get0_private_key(eckey1);
	priv2 = EC_KEY_get0_private_key(eckey2);
	if (priv1 != NULL || priv2 != NULL) {
		if (priv1 == NULL || priv2 == NULL) {
			DST_RET(false);
		}
		if (BN_cmp(priv1, priv2) != 0) {
			DST_RET(false);
		}
	}
	ret = true;

err:
	if (eckey1 != NULL) {
		EC_KEY_free(eckey1);
	}
	if (eckey2 != NULL) {
		EC_KEY_free(eckey2);
	}
	return (ret);
}

static isc_result_t
ecdsa_generate(dst_key_t *key, int group_nid) {
	isc_result_t ret = ISC_R_SUCCESS;
	EVP_PKEY *pkey;
	EC_KEY *eckey = NULL;

	eckey = EC_KEY_new_by_curve_name(group_nid);
	if (eckey == NULL) {
		return (dst__openssl_toresult2("EC_KEY_new_by_curve_name",
					       DST_R_OPENSSLFAILURE));
	}

	if (EC_KEY_generate_key(eckey) != 1) {
		DST_RET(dst__openssl_toresult2("EC_KEY_generate_key",
					       DST_R_OPENSSLFAILURE));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		DST_RET(ISC_R_NOMEMORY);
	}
	if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
		EVP_PKEY_free(pkey);
		DST_RET(ISC_R_FAILURE);
	}
	key->keydata.pkey = pkey;
	ret = ISC_R_SUCCESS;

err:
	EC_KEY_free(eckey);
	return (ret);
}

static isc_result_t
ecdsa_todns(EVP_PKEY *pkey, isc_buffer_t *data) {
	isc_result_t ret;
	EC_KEY *eckey = NULL;
	isc_region_t r;
	int len;
	unsigned char *cp;
	unsigned char buf[DNS_KEY_ECDSA384SIZE + 1];

	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (eckey == NULL) {
		return (dst__openssl_toresult(ISC_R_FAILURE));
	}
	len = i2o_ECPublicKey(eckey, NULL);
	/* skip form */
	len--;

	isc_buffer_availableregion(data, &r);
	if (r.length < (unsigned int)len) {
		DST_RET(ISC_R_NOSPACE);
	}
	cp = buf;
	if (!i2o_ECPublicKey(eckey, &cp)) {
		DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
	}
	memmove(r.base, buf + 1, len);
	isc_buffer_add(data, len);
	ret = ISC_R_SUCCESS;

err:
	EC_KEY_free(eckey);
	return (ret);
}

static isc_result_t
ecdsa_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	EVP_PKEY *pkey;
	EC_KEY *eckey = NULL;
	const BIGNUM *privkey;
	dst_private_t priv;
	unsigned char *buf = NULL;
	unsigned short i;

	if (key->keydata.pkey == NULL) {
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	pkey = key->keydata.pkey;
	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (eckey == NULL) {
		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}
	privkey = EC_KEY_get0_private_key(eckey);
	if (privkey == NULL) {
		ret = dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		goto err;
	}

	buf = isc_mem_get(key->mctx, BN_num_bytes(privkey));

	i = 0;

	priv.elements[i].tag = TAG_ECDSA_PRIVATEKEY;
	priv.elements[i].length = BN_num_bytes(privkey);
	BN_bn2bin(privkey, buf);
	priv.elements[i].data = buf;
	i++;

	if (key->engine != NULL) {
		priv.elements[i].tag = TAG_ECDSA_ENGINE;
		priv.elements[i].length = (unsigned short)strlen(key->engine) +
					  1;
		priv.elements[i].data = (unsigned char *)key->engine;
		i++;
	}

	if (key->label != NULL) {
		priv.elements[i].tag = TAG_ECDSA_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}

	priv.nelements = i;
	ret = dst__privstruct_writefile(key, &priv, directory);

err:
	EC_KEY_free(eckey);
	if (buf != NULL) {
		isc_mem_put(key->mctx, buf, BN_num_bytes(privkey));
	}
	return (ret);
}

#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
static isc_result_t
eddsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	isc_buffer_t *nbuf = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t ret;

	ret = isc_buffer_copyregion(buf, data);
	if (ret == ISC_R_SUCCESS) {
		return (ISC_R_SUCCESS);
	}

	length = isc_buffer_length(buf) + data->length + 64;
	isc_buffer_allocate(dctx->mctx, &nbuf, length);
	isc_buffer_usedregion(buf, &r);
	(void)isc_buffer_copyregion(nbuf, &r);
	(void)isc_buffer_copyregion(nbuf, data);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = nbuf;

	return (ISC_R_SUCCESS);
}

static isc_result_t
eddsa_sign(dst_context_t *dctx, isc_buffer_t *sig, isc_region_t *sigreg,
	   size_t siglen, EVP_PKEY *pkey) {
	isc_result_t ret;
	isc_region_t tbsreg;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignInit", ISC_R_FAILURE));
	}
	if (EVP_DigestSign(ctx, sigreg->base, &siglen, tbsreg.base,
			   tbsreg.length) != 1) {
		DST_RET(dst__openssl_toresult3(dctx->category, "EVP_DigestSign",
					       DST_R_SIGNFAILURE));
	}
	isc_buffer_add(sig, (unsigned int)siglen);
	ret = ISC_R_SUCCESS;

err:
	EVP_MD_CTX_free(ctx);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);
}

static isc_result_t
eddsa_verify(dst_context_t *dctx, const isc_region_t *sig, size_t siglen,
	     EVP_PKEY *pkey) {
	isc_result_t ret;
	int status;
	isc_region_t tbsreg;
	EVP_MD_CTX *ctx;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestVerifyInit", ISC_R_FAILURE));
	}

	status = EVP_DigestVerify(ctx, sig->base, siglen, tbsreg.base,
				  tbsreg.length);

	switch (status) {
	case 1:
		ret = ISC_R_SUCCESS;
		break;
	case 0:
		ret = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		ret = dst__openssl_toresult3(dctx->category, "EVP_DigestVerify",
					     DST_R_VERIFYFAILURE);
		break;
	}

err:
	EVP_MD_CTX_free(ctx);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;
	return (ret);
}

static bool
eddsa_isprivate(EVP_PKEY *pkey, size_t len) {
	if (EVP_PKEY_get_raw_private_key(pkey, NULL, &len) == 1 && len > 0) {
		return (true);
	}
	/* can check if first error is EC_R_INVALID_PRIVATE_KEY */
	while (ERR_get_error() != 0) {
		/**/
	}
	return (false);
}

static isc_result_t
eddsa_todns(EVP_PKEY *pkey, isc_buffer_t *data, size_t len) {
	isc_region_t r;
	isc_buffer_availableregion(data, &r);
	if (r.length < len) {
		return (ISC_R_NOSPACE);
	}
	if (EVP_PKEY_get_raw_public_key(pkey, r.base, &len) != 1) {
		return (dst__openssl_toresult(ISC_R_FAILURE));
	}
	isc_buffer_add(data, len);
	return (ISC_R_SUCCESS);
}

static isc_result_t
eddsa_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	dst_private_t priv;
	unsigned char *buf = NULL;
	size_t len;
	int i;

	if (key->keydata.pkey == NULL) {
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	i = 0;

	if (opensslec_isprivate(key)) {
		if (key->key_alg == DST_ALG_ED25519) {
			len = DNS_KEY_ED25519SIZE;
		} else {
			len = DNS_KEY_ED448SIZE;
		}
		buf = isc_mem_get(key->mctx, len);
		if (EVP_PKEY_get_raw_private_key(key->keydata.pkey, buf,
						 &len) != 1) {
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		}
		priv.elements[i].tag = TAG_EDDSA_PRIVATEKEY;
		priv.elements[i].length = len;
		priv.elements[i].data = buf;
		i++;
	}
	if (key->engine != NULL) {
		priv.elements[i].tag = TAG_EDDSA_ENGINE;
		priv.elements[i].length = (unsigned short)strlen(key->engine) +
					  1;
		priv.elements[i].data = (unsigned char *)key->engine;
		i++;
	}
	if (key->label != NULL) {
		priv.elements[i].tag = TAG_EDDSA_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}

	priv.nelements = i;
	ret = dst__privstruct_writefile(key, &priv, directory);

err:
	if (buf != NULL) {
		isc_mem_put(key->mctx, buf, len);
	}
	return (ret);
}
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */

/*
 * opensslec_createctx
 */
static isc_result_t
opensslec_createctx(dst_key_t *key, dst_context_t *dctx) {
	dst_key_t *dkey;
	isc_result_t ret;
	isc_buffer_t *buf = NULL;
	int baseid = EVP_PKEY_NONE;

	UNUSED(key);

	REQUIRE(dctx != NULL);

	dkey = dctx->key;
	ret = key_check(dkey, &baseid, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	/* ECDSA */
	if (baseid == EVP_PKEY_EC) {
		EVP_MD_CTX *evp_md_ctx;
		const EVP_MD *type = NULL;

		evp_md_ctx = EVP_MD_CTX_create();
		if (evp_md_ctx == NULL) {
			return (ISC_R_NOMEMORY);
		}
		if (dkey->key_alg == DST_ALG_ECDSA256) {
			type = EVP_sha256();
		} else {
			type = EVP_sha384();
		}

		if (!EVP_DigestInit_ex(evp_md_ctx, type, NULL)) {
			EVP_MD_CTX_destroy(evp_md_ctx);
			return (dst__openssl_toresult3(dctx->category,
						       "EVP_DigestInit_ex",
						       ISC_R_FAILURE));
		}

		dctx->ctxdata.evp_md_ctx = evp_md_ctx;
		return (ISC_R_SUCCESS);
	}

	/* EDDSA */
	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;
	return (ISC_R_SUCCESS);
}

/*
 * opensslec_destroyctx
 */
static void
opensslec_destroyctx(dst_context_t *dctx) {
	isc_result_t ret;
	dst_key_t *key;
	int baseid = EVP_PKEY_NONE;

	REQUIRE(dctx != NULL);

	key = dctx->key;
	ret = key_check(key, &baseid, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return;
	}

	if (baseid == EVP_PKEY_EC) {
		/* ECDSA */
		EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
		if (evp_md_ctx != NULL) {
			EVP_MD_CTX_destroy(evp_md_ctx);
			dctx->ctxdata.evp_md_ctx = NULL;
		}
	} else {
		/* EDDSA */
		isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
		if (buf != NULL) {
			isc_buffer_free(&buf);
		}
		dctx->ctxdata.generic = NULL;
	}
}

/*
 * opensslec_adddata
 */
static isc_result_t
opensslec_adddata(dst_context_t *dctx, const isc_region_t *data) {
	dst_key_t *key;
	isc_result_t ret;
	int baseid = EVP_PKEY_NONE;

	REQUIRE(dctx != NULL);

	key = dctx->key;
	ret = key_check(key, &baseid, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	/* ECDSA */
	if (baseid == EVP_PKEY_EC) {
		EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
		if (!EVP_DigestUpdate(evp_md_ctx, data->base, data->length)) {
			return (dst__openssl_toresult3(dctx->category,
						       "EVP_DigestUpdate",
						       ISC_R_FAILURE));
		}
		return (ISC_R_SUCCESS);
	}

#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
	return (eddsa_adddata(dctx, data));
#else
	return (ISC_R_NOTIMPLEMENTED);
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
}

/*
 * opensslec_sign
 */
static isc_result_t
opensslec_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t ret;
	dst_key_t *key;
	isc_region_t sigreg;
	EVP_PKEY *pkey;
	int baseid = EVP_PKEY_NONE;
	size_t siglen;

	REQUIRE(dctx != NULL);

	key = dctx->key;
	ret = key_check(key, &baseid, NULL, NULL, &siglen);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	pkey = key->keydata.pkey;

	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < siglen) {
		return (ISC_R_NOSPACE);
	}

	/* ECDSA */
	if (baseid == EVP_PKEY_EC) {
		return (ecdsa_sign(dctx, sig, &sigreg, siglen, pkey));
	}

#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
	return (eddsa_sign(dctx, sig, &sigreg, siglen, pkey));
#else
	return (ISC_R_NOTIMPLEMENTED);
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
}

/*
 * opensslec_verify
 */
static isc_result_t
opensslec_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key;
	EVP_PKEY *pkey;
	int baseid = EVP_PKEY_NONE;
	size_t siglen = 0;

	REQUIRE(dctx != NULL);

	key = dctx->key;
	ret = key_check(key, &baseid, NULL, NULL, &siglen);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	pkey = key->keydata.pkey;

	if (sig->length != (unsigned int)siglen) {
		return (DST_R_VERIFYFAILURE);
	}

	/* ECDSA */
	if (baseid == EVP_PKEY_EC) {
		return (ecdsa_verify(dctx, sig, pkey));
	}

#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
	return (eddsa_verify(dctx, sig, siglen, pkey));
#else
	return (ISC_R_NOTIMPLEMENTED);
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
}

/*
 * opensslec_compare
 */
static bool
opensslec_compare(const dst_key_t *key1, const dst_key_t *key2) {
	int status, id1 = EVP_PKEY_NONE, id2 = EVP_PKEY_NONE;
	isc_result_t ret;
	bool cmp;
	EVP_PKEY *pkey1;
	EVP_PKEY *pkey2;

	REQUIRE(key1 != NULL);
	REQUIRE(key2 != NULL);

	ret = key_check(key1, &id1, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}
	ret = key_check(key2, &id2, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	if (id1 != id2) {
		return (false);
	}

	pkey1 = key1->keydata.pkey;
	pkey2 = key2->keydata.pkey;
	if (pkey1 == NULL && pkey2 == NULL) {
		return (true);
	} else if (pkey1 == NULL || pkey2 == NULL) {
		return (false);
	}

	status = EVP_PKEY_cmp(pkey1, pkey2);
	if (status != 1) {
		return (false);
	}

	if (id1 == EVP_PKEY_EC) {
		/* ECDSA */
		cmp = (ecdsa_compare(pkey1, pkey2));
	} else {
		/* EDDSA */
		cmp = true;
	}

	return (cmp);
}

/*
 * opensslec_generate
 */
static isc_result_t
opensslec_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	isc_result_t ret;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int baseid = EVP_PKEY_NONE;
	int nid = 0, status;
	size_t len, blocksize;

	UNUSED(unused);
	UNUSED(callback);

	ret = key_check(key, &baseid, &nid, &len, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	blocksize = (baseid == EVP_PKEY_EC) ? 4 : 8;
	key->key_size = len * blocksize;

	/* ECDSA */
	if (baseid == EVP_PKEY_EC) {
		return (ecdsa_generate(key, nid));
	}

	/* EDDSA */
	ctx = EVP_PKEY_CTX_new_id(nid, NULL);
	if (ctx == NULL) {
		return (dst__openssl_toresult2("EVP_PKEY_CTX_new_id",
					       DST_R_OPENSSLFAILURE));
	}

	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen_init",
					       DST_R_OPENSSLFAILURE));
	}

	status = EVP_PKEY_keygen(ctx, &pkey);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen",
					       DST_R_OPENSSLFAILURE));
	}

	key->keydata.pkey = pkey;
	ret = ISC_R_SUCCESS;

err:
	EVP_PKEY_CTX_free(ctx);
	return (ret);
}

/*
 * opensslec_isprivate
 */
static bool
opensslec_isprivate(const dst_key_t *key) {
	isc_result_t ret;
	EVP_PKEY *pkey;
	int baseid = EVP_PKEY_NONE;
	size_t len;

	ret = key_check(key, &baseid, NULL, &len, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	pkey = key->keydata.pkey;
	if (pkey == NULL) {
		return (false);
	}

	/* ECDSA */
	if (baseid == EVP_PKEY_EC) {
		bool isprivate;
		EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);

		isprivate = (eckey != NULL &&
			     EC_KEY_get0_private_key(eckey) != NULL);
		if (eckey != NULL) {
			EC_KEY_free(eckey);
		}
		return (isprivate);
	}

#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
	return (eddsa_isprivate(pkey, len));
#else
	return (false);
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
}

/*
 * opensslec_destroy
 */
static void
opensslec_destroy(dst_key_t *key) {
	EVP_PKEY *pkey;

	REQUIRE(key != NULL);
	REQUIRE(key->keydata.pkey != NULL);

	pkey = key->keydata.pkey;
	EVP_PKEY_free(pkey);
	key->keydata.pkey = NULL;
}

/*
 * opensslec_todns
 */
static isc_result_t
opensslec_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	EVP_PKEY *pkey;
	size_t len;
	int baseid = EVP_PKEY_NONE;

	REQUIRE(key != NULL);
	REQUIRE(key->keydata.pkey != NULL);

	ret = key_check(key, &baseid, NULL, &len, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	pkey = key->keydata.pkey;

	if (baseid == EVP_PKEY_EC) {
		return (ecdsa_todns(pkey, data));
	}

#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
	return (eddsa_todns(pkey, data, len));
#else
	return (ISC_R_NOTIMPLEMENTED);
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
}

/*
 * opensslec_fromdns
 */
static isc_result_t
opensslec_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	isc_region_t r;
	int baseid = EVP_PKEY_NONE;
	size_t len, blocksize;
	EVP_PKEY *pkey = NULL;

	ret = key_check(key, &baseid, NULL, &len, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return (ISC_R_SUCCESS);
	}
	if (r.length < len) {
		return (DST_R_INVALIDPUBLICKEY);
	}

	len = r.length;
	ret = key2ossl(key, false, r.base, &len, &pkey);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	blocksize = (baseid == EVP_PKEY_EC) ? 4 : 8;
	isc_buffer_forward(data, len);
	key->keydata.pkey = pkey;
	key->key_size = len * blocksize;
	return (ISC_R_SUCCESS);
}

/*
 * opensslec_tofile
 */
static isc_result_t
opensslec_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	int baseid = EVP_PKEY_NONE;

	ret = key_check(key, &baseid, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	/* ECDSA */
	if (baseid == EVP_PKEY_EC) {
		return (ecdsa_tofile(key, directory));
	}

#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
	return (eddsa_tofile(key, directory));
#else
	return (ISC_R_NOTIMPLEMENTED);
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
}

/*
 * opensslec_parse
 */
static isc_result_t
opensslec_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret = ISC_R_SUCCESS;
	int i, privkey_index = -1;
	const char *engine = NULL;
	const char *label = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pubpkey = NULL;
	isc_mem_t *mctx = key->mctx;
	size_t len;
	int baseid = EVP_PKEY_NONE;
	unsigned int alg, blocksize;

	ret = key_check(key, &baseid, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	if (baseid == EVP_PKEY_EC) {
		alg = DST_ALG_ECDSA256;
		blocksize = 4;
	} else {
		alg = DST_ALG_ED25519;
		blocksize = 8;
	}

	char algstr[DNS_NAME_FORMATSIZE];
	dns_secalg_format((dns_secalg_t)alg, algstr, sizeof(algstr));

	/* read private key file */
	ret = dst__privstruct_parse(key, alg, lexer, mctx, &priv);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}

	if (key->external) {
		if (priv.nelements != 0) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		if (pub == NULL) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		key->keydata.pkey = pub->keydata.pkey;
		pub->keydata.pkey = NULL;
		DST_RET(ISC_R_SUCCESS);
	}

	if (pub != NULL && pub->keydata.pkey != NULL) {
		pubpkey = pub->keydata.pkey;
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_ECDSA_ENGINE:
		case TAG_EDDSA_ENGINE:
			engine = (char *)priv.elements[i].data;
			break;
		case TAG_ECDSA_LABEL:
		case TAG_EDDSA_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		case TAG_ECDSA_PRIVATEKEY:
		case TAG_EDDSA_PRIVATEKEY:
			privkey_index = i;
			break;
		default:
			break;
		}
	}

	if (label != NULL) {
		ret = opensslec_fromlabel(key, engine, label, NULL);
		if (ret != ISC_R_SUCCESS) {
			goto err;
		}
		if (ec_check(key->keydata.pkey, pubpkey) != ISC_R_SUCCESS) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		DST_RET(ISC_R_SUCCESS);
	}

	if (privkey_index < 0) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}

	len = priv.elements[privkey_index].length;
	ret = key2ossl(key, true, priv.elements[privkey_index].data, &len,
		       &pkey);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}
	if (baseid == EVP_PKEY_EC && pubpkey != NULL) {
		EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);
		EC_KEY *pubeckey = EVP_PKEY_get1_EC_KEY(pubpkey);
		const EC_POINT *pt = NULL;
		if (pubeckey != NULL) {
			pt = EC_KEY_get0_public_key(pubeckey);
		}
		if (pt != NULL && EC_KEY_set_public_key(eckey, pt) == 1) {
			if (EC_KEY_check_key(eckey) != 1) {
				DST_RET(DST_R_INVALIDPRIVATEKEY);
			}
		}
	}

	if (ec_check(pkey, pubpkey) != ISC_R_SUCCESS) {
		EVP_PKEY_free(pkey);
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}

	key->keydata.pkey = pkey;
	key->key_size = len * blocksize;
	ret = ISC_R_SUCCESS;

err:
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return (ret);
}

/*
 * openssl_fromlabel
 */
static isc_result_t
opensslec_fromlabel(dst_key_t *key, const char *engine, const char *label,
		    const char *pin) {
#if !defined(OPENSSL_NO_ENGINE)
	isc_result_t ret = ISC_R_SUCCESS;
	ENGINE *e;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pubpkey = NULL;
	int baseid = EVP_PKEY_NONE;

	UNUSED(pin);

	ret = key_check(key, &baseid, NULL, NULL, NULL);
	if (ret != ISC_R_SUCCESS) {
		return (ret);
	}

	if (engine == NULL) {
		return (DST_R_NOENGINE);
	}
	e = dst__openssl_getengine(engine);
	if (e == NULL) {
		return (DST_R_NOENGINE);
	}

	pkey = ENGINE_load_private_key(e, label, NULL, NULL);
	if (pkey == NULL) {
		return (dst__openssl_toresult2("ENGINE_load_private_key",
					       ISC_R_NOTFOUND));
	}
	if (EVP_PKEY_base_id(pkey) != baseid) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	/* TODO: check group nid */

	pubpkey = ENGINE_load_public_key(e, label, NULL, NULL);
	if (ec_check(pkey, pubpkey) != ISC_R_SUCCESS) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}

	key->engine = isc_mem_strdup(key->mctx, engine);
	key->label = isc_mem_strdup(key->mctx, label);
	key->key_size = EVP_PKEY_bits(pkey);
	key->keydata.pkey = pkey;
	pkey = NULL;
	ret = ISC_R_SUCCESS;

err:
	if (pubpkey != NULL) {
		EVP_PKEY_free(pubpkey);
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	return (ret);
#else /* if !defined(OPENSSL_NO_ENGINE) */
	UNUSED(key);
	UNUSED(engine);
	UNUSED(label);
	UNUSED(pin);
	return (DST_R_NOENGINE);
#endif /* if !defined(OPENSSL_NO_ENGINE) */
}

static dst_func_t opensslec_functions = {
	opensslec_createctx,
	NULL, /*%< createctx2 */
	opensslec_destroyctx,
	opensslec_adddata,
	opensslec_sign,
	opensslec_verify,
	NULL, /*%< verify2 */
	NULL, /*%< computesecret */
	opensslec_compare,
	NULL, /*%< paramcompare */
	opensslec_generate,
	opensslec_isprivate,
	opensslec_destroy,
	opensslec_todns,
	opensslec_fromdns,
	opensslec_tofile,
	opensslec_parse,
	NULL, /*%< cleanup */
	opensslec_fromlabel,
	NULL, /*%< dump */
	NULL, /*%< restore */
};

isc_result_t
dst__opensslec_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL) {
		*funcp = &opensslec_functions;
	}
	return (ISC_R_SUCCESS);
}
