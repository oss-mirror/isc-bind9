/*
 * Portions Copyright (c) 1995-1999 by Network Associates, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND NETWORK ASSOCIATES
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * NETWORK ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id: dst_api.c,v 1.19 1999/10/26 19:31:52 bwelling Exp $
 */

#include <config.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/dir.h>
#include <isc/error.h>
#include <isc/int.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/region.h>
#include <dns/rdata.h>
#include <dns/keyvalues.h>

#include <openssl/rand.h>

#include "dst_internal.h"
#include "dst/result.h"

#define KEY_MAGIC	0x44535421U	/* DST! */

#define VALID_KEY(key) (key != NULL && key->magic == KEY_MAGIC)

dst_func *dst_t_func[DST_MAX_ALGS];

static isc_mem_t *dst_memory_pool = NULL;
static isc_once_t once = ISC_ONCE_INIT;
static isc_mutex_t random_lock;

/* Static functions */
static void		initialize(void);
static dst_key_t *	get_key_struct(const char *name, const int alg,
				       const int flags, const int protocol,
				       const int bits, isc_mem_t *mctx);
static dst_result_t	read_public_key(const char *name,
					const isc_uint16_t id, int in_alg,
					isc_mem_t *mctx, dst_key_t **keyp);
static dst_result_t	write_public_key(const dst_key_t *key);

/*
 *  dst_supported_algorithm
 *	This function determines if the crypto system for the specified
 *	algorithm is present.
 *  Parameters
 *	alg		The algorithm to test
 *  Returns
 *	ISC_TRUE	The algorithm is available.
 *	ISC_FALSE	The algorithm is not available.
 */
isc_boolean_t
dst_supported_algorithm(const int alg) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	if (alg >= DST_MAX_ALGS || dst_t_func[alg] == NULL)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

/*
 * dst_sign
 *	An incremental signing function.  Data is signed in steps.
 *	First the context must be initialized (DST_SIGMODE_INIT).
 *	Then data is hashed (DST_SIGMODE_UPDATE).  Finally the signature
 *	itself is created (DST_SIGMODE_FINAL).  This function can be called
 *	once with DST_SIGMODE_ALL set, or it can be called separately 
 *	for each step.  The UPDATE step may be repeated.
 * Parameters
 *	mode		A bit mask specifying operation(s) to be performed.
 *			  DST_SIGMODE_INIT	Initialize digest
 *			  DST_SIGMODE_UPDATE	Add data to digest
 *			  DST_SIGMODE_FINAL	Generate signature
 *			  DST_SIGMODE_ALL	Perform all operations
 *	key		The private key used to sign the data
 *	context		The state of the operation
 *	data		The data to be signed.
 *	sig		The buffer to which the signature will be written.
 * Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t
dst_sign(const unsigned int mode, dst_key_t *key, dst_context_t *context, 
	 isc_region_t *data, isc_buffer_t *sig)
{
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE((mode & DST_SIGMODE_ALL) != 0);

	if ((mode & DST_SIGMODE_UPDATE) != 0)
		REQUIRE(data != NULL && data->base != NULL);

	if ((mode & DST_SIGMODE_FINAL) != 0)
		REQUIRE(sig != NULL);

	if (dst_supported_algorithm(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);
	if (key->opaque == NULL)
		return (DST_R_NULLKEY);
	if (key->func->sign == NULL)
		return (DST_R_NOTPRIVATEKEY);

	return (key->func->sign(mode, key, (void **)context, data, sig,
				key->mctx));
}


/*
 *  dst_verify
 *	An incremental verify function.  Data is verified in steps.
 *	First the context must be initialized (DST_SIGMODE_INIT).
 *	Then data is hashed (DST_SIGMODE_UPDATE).  Finally the signature
 *	is verified (DST_SIGMODE_FINAL).  This function can be called
 *	once with DST_SIGMODE_ALL set, or it can be called separately
 *	for each step.  The UPDATE step may be repeated.
 *  Parameters
 *	mode		A bit mask specifying operation(s) to be performed.
 *			  DST_SIGMODE_INIT	Initialize digest
 *			  DST_SIGMODE_UPDATE	Add data to digest
 *			  DST_SIGMODE_FINAL	Verify signature
 *			  DST_SIGMODE_ALL	Perform all operations
 *	key		The public key used to verify the signature.
 *	context		The state of the operation
 *	data		The data to be digested.
 *	sig		The signature.
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

dst_result_t
dst_verify(const unsigned int mode, dst_key_t *key, dst_context_t *context, 
	   isc_region_t *data, isc_region_t *sig)
{
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE((mode & DST_SIGMODE_ALL) != 0);

	if ((mode & DST_SIGMODE_UPDATE) != 0)
		REQUIRE(data != NULL && data->base != NULL);

	if ((mode & DST_SIGMODE_FINAL) != 0)
		REQUIRE(sig != NULL && sig->base != NULL);

	if (dst_supported_algorithm(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);
	if (key->opaque == NULL)
		return (DST_R_NULLKEY);
	if (key->func->verify == NULL)
		return (DST_R_NOTPUBLICKEY);

	return (key->func->verify(mode, key, (void **)context, data, sig,
				  key->mctx));
}

/*
 *  dst_digest
 *	An incremental digest function.  Data is digested in steps.
 *	First the context must be initialized (DST_SIGMODE_INIT).
 *	Then data is hashed (DST_SIGMODE_UPDATE).  Finally the digest
 *	is generated (DST_SIGMODE_FINAL).  This function can be called
 *	once with DST_SIGMODE_ALL set, or it can be called separately
 *	for each step.  The UPDATE step may be repeated.
 *  Parameters
 *	mode		A bit mask specifying operation(s) to be performed.
 *			  DST_SIGMODE_INIT	Initialize digest
 *			  DST_SIGMODE_UPDATE	Add data to digest
 *			  DST_SIGMODE_FINAL	Complete digest
 *			  DST_SIGMODE_ALL	Perform all operations
 *	alg		The digest algorithm to use
 *	context		The state of the operation
 *	data		The data to be digested.
 *	sig		The sdigest.
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t
dst_digest(const unsigned int mode, const unsigned int alg,
           dst_context_t *context, isc_region_t *data, isc_buffer_t *digest)
{
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE((mode & DST_SIGMODE_ALL) != 0);

	if ((mode & DST_SIGMODE_UPDATE) != 0)
		REQUIRE(data != NULL && data->base != NULL);

	if ((mode & DST_SIGMODE_FINAL) != 0)
		REQUIRE(digest != NULL);

	if (alg != DST_DIGEST_MD5)
		return (DST_R_UNSUPPORTEDALG);

	return (dst_s_md5(mode, context, data, digest, dst_memory_pool));
}


/*
 * dst_computesecret
 *	A function to compute a shared secret from two (Diffie-Hellman) keys.
 * Parameters
 *      pub             The public key
 *      priv            The private key
 *      secret          A buffer into which the secret is written
 * Returns
 *      ISC_R_SUCCESS   Success
 *      !ISC_R_SUCCESS  Failure
 */
dst_result_t
dst_computesecret(const dst_key_t *pub, const dst_key_t *priv,
		  isc_buffer_t *secret) 
{
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(pub) && VALID_KEY(priv));
	REQUIRE(secret != NULL);

	if (dst_supported_algorithm(pub->key_alg)  == ISC_FALSE ||
	    dst_supported_algorithm(priv->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if (pub->opaque == NULL || priv->opaque == NULL)
		return (DST_R_NULLKEY);

	if (pub->key_alg != priv->key_alg ||
	    pub->func->computesecret == NULL ||
	    priv->func->computesecret == NULL)
		return (DST_R_KEYCANNOTCOMPUTESECRET);

	if (dst_key_isprivate(priv) == ISC_FALSE)
		return (DST_R_NOTPRIVATEKEY);

	return (pub->func->computesecret(pub, priv, secret));
}

/*
 *  dst_key_tofile
 *	Writes a key to disk.  The key can either be a public or private key.
 *	The public key is written in DNS format and the private key is
 *	written as a set of base64 encoded values.
 *  Parameters
 *	key		The key to be written.
 *	type		Either DST_PUBLIC or DST_PRIVATE, or both
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t 
dst_key_tofile(const dst_key_t *key, const int type) {
	int ret = ISC_R_SUCCESS;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));

	if (dst_supported_algorithm(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if ((type & (DST_TYPE_PRIVATE | DST_TYPE_PUBLIC)) == 0)
		return (DST_R_UNSUPPORTEDTYPE);

	if (type & DST_TYPE_PUBLIC) 
		if ((ret = write_public_key(key)) != ISC_R_SUCCESS)
			return (ret);

	if ((type & DST_TYPE_PRIVATE) &&
	    (key->key_flags & DNS_KEYFLAG_TYPEMASK) != DNS_KEYTYPE_NOKEY)
	{
		ret = key->func->to_file(key);
		if (ret != ISC_R_SUCCESS)
			return (ret);
	}

	return (ret);
}

/*
 *  dst_key_fromfile
 *	Reads a key from disk.  The key can either be a public or private
 *	key, and is specified by name, algorithm, and id.
 *  Parameters
 *	name	The key name.
 *	id	The id of the key.
 *	alg	The algorithm of the key.
 *	type	Either DST_PUBLIC or DST_PRIVATE
 *	mctx	Memory context used to allocate key structure
 *	keyp	Returns the new key
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t
dst_key_fromfile(const char *name, const isc_uint16_t id, const int alg,
		 const int type, isc_mem_t *mctx, dst_key_t **keyp)
{
	dst_key_t *key = NULL, *pubkey = NULL;
	dst_result_t ret;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(name != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(keyp != NULL);

	*keyp = NULL;
	if (dst_supported_algorithm(alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if ((type & (DST_TYPE_PRIVATE | DST_TYPE_PUBLIC)) == 0)
		return (DST_R_UNSUPPORTEDTYPE);

	ret = read_public_key(name, id, alg, mctx, &pubkey);
	if (ret == ISC_R_NOTFOUND && (type & DST_TYPE_PUBLIC) == 0)
		key = get_key_struct(name, alg, 0, 0, 0, mctx);
	else if (ret != ISC_R_SUCCESS)
		return (ret);
	else {
		if (type == DST_TYPE_PUBLIC ||
		    (pubkey->key_flags & DNS_KEYFLAG_TYPEMASK) ==
		     DNS_KEYTYPE_NOKEY)
		{
			*keyp = pubkey;
			return (ISC_R_SUCCESS);
		}
	
		key = get_key_struct(name, pubkey->key_alg, pubkey->key_flags,
					   pubkey->key_proto, 0, mctx);
		dst_key_free(pubkey);
	}

	if (key == NULL)
		return (ISC_R_NOMEMORY);

	/* Fill in private key and some fields in the general key structure */
	ret = key->func->from_file(key, id, mctx);
	if (ret != ISC_R_SUCCESS) {
		dst_key_free(key);
		return (ret);
	}

	*keyp = key;
	return (ISC_R_SUCCESS);
}

/*
 *  dst_key_todns
 *	Function to encode a public key into DNS KEY format
 *  Parameters
 *	key		Key structure to encode.
 *	target		Buffer to write the encoded key into.
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t
dst_key_todns(const dst_key_t *key, isc_buffer_t *target) {
	isc_region_t r;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(target != NULL);

	if (dst_supported_algorithm(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	isc_buffer_available(target, &r);
	if (r.length < 4)
		return (ISC_R_NOSPACE);
	isc_buffer_putuint16(target, (isc_uint16_t)(key->key_flags & 0xffff));
	isc_buffer_putuint8(target, (isc_uint8_t)key->key_proto);
	isc_buffer_putuint8(target, (isc_uint8_t)key->key_alg);

	if (key->key_flags & DNS_KEYFLAG_EXTENDED) {
		isc_buffer_available(target, &r);
		if (r.length < 2)
			return (ISC_R_NOSPACE);
		isc_buffer_putuint16(target,
				     (isc_uint16_t)((key->key_flags >> 16)
						    & 0xffff));
	}

	if (key->opaque == NULL) /* NULL KEY */
		return (ISC_R_SUCCESS);

	return (key->func->to_dns(key, target));
}

/*
 *  dst_key_fromdns
 *	This function converts the contents of a DNS KEY RR into a key
 *  Paramters
 *	name		Name of the new key
 *	source		A buffer containing the KEY RR
 *	mctx		The memory context used to allocate the key
 *	keyp		Returns the new key
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

dst_result_t
dst_key_fromdns(const char *name, isc_buffer_t *source, isc_mem_t *mctx,
		dst_key_t **keyp)
{
	isc_region_t r;
	isc_uint8_t alg, proto;
	isc_uint32_t flags, extflags;
	dst_result_t ret;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE (name != NULL);
	REQUIRE (source != NULL);
	REQUIRE (mctx != NULL);
	REQUIRE (keyp != NULL);

	isc_buffer_remaining(source, &r);
	if (r.length < 4) /* 2 bytes of flags, 1 proto, 1 alg */
		return (DST_R_INVALIDPUBLICKEY);
	flags = isc_buffer_getuint16(source);
	proto = isc_buffer_getuint8(source);
	alg = isc_buffer_getuint8(source);

	if (!dst_supported_algorithm(alg))
		return (DST_R_UNSUPPORTEDALG);

	if (flags & DNS_KEYFLAG_EXTENDED) {
		isc_buffer_remaining(source, &r);
		if (r.length < 2)
			return (DST_R_INVALIDPUBLICKEY);
		extflags = isc_buffer_getuint16(source);
		flags |= (extflags << 16);
	}

	*keyp = get_key_struct(name, alg, flags, proto, 0, mctx);
	if (*keyp == NULL)
		return (ISC_R_NOMEMORY);

	ret = (*keyp)->func->from_dns(*keyp, source, mctx);
	if (ret != ISC_R_SUCCESS) 
		dst_key_free((*keyp));
	return (ret);
}


/*
 *  dst_key_frombuffer
 *	Function to convert raw data into a public key.  The raw data format
 *	is basically DNS KEY rdata format.
 *  Parameters
 *	name		The key name
 *	alg		The algorithm
 *	flags		The key's flags
 *	protocol	The key's protocol
 *	source		A buffer containing the key
 *	mctx		The memory context used to allocate the key
 *	keyp		Returns the new key
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t
dst_key_frombuffer(const char *name, const int alg, const int flags,
		   const int protocol, isc_buffer_t *source, isc_mem_t *mctx,
		   dst_key_t **keyp)
{
	dst_result_t ret;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(name != NULL);
	REQUIRE(source != NULL);
	REQUIRE(mctx != NULL);

	if (dst_supported_algorithm(alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	*keyp = get_key_struct(name, alg, flags, protocol, 0, mctx);

	if (*keyp == NULL)
		return (ISC_R_NOMEMORY);

	ret = (*keyp)->func->from_dns((*keyp), source, mctx);
	if (ret != ISC_R_SUCCESS) {
		dst_key_free((*keyp));
		return (ret);
	}
	return (ISC_R_SUCCESS);
}

/*
 *  dst_key_tobuffer
 *	Function to convert a public key into raw data.  The raw data format
 *	is basically DNS KEY rdata format.
 *  Parameters
 *	key		The key
 *	target		The buffer to be written into.
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t 
dst_key_tobuffer(const dst_key_t *key, isc_buffer_t *target) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(target != NULL);

	if (dst_supported_algorithm(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	return (key->func->to_dns(key, target));
}

/*
 *  dst_key_generate
 *	Generate a public/private keypair.
 *  Parameters
 *	name	Name of the new key.  Used to create key files
 *			K<name>+<alg>+<id>.public
 *			K<name>+<alg>+<id>.private
 *	alg	The algorithm to use
 *	bits	Size of the new key in bits
 *	param	Algorithm specific
 *		RSA: exponent
 *			0	use exponent 3
 *			!0	use Fermat4 (2^16 + 1)
 *		DH: generator
 *			0	default - use well-known prime if bits == 768
 *				or 1024, otherwise use generator 2
 *			!0	use this value as the generator
 *		DSA/HMACMD5: unused
 *	flags	The default value of the DNS Key flags.
 *	protocol Default value of the DNS Key protocol field.
 *	mctx	The memory context used to allocate the key
 *	keyp	Returns the new key
 *
 *  Return
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t
dst_key_generate(const char *name, const int alg, const int bits,
		 const int exp, const int flags, const int protocol,
		 isc_mem_t *mctx, dst_key_t **keyp)
{
	dst_result_t ret;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(name != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(keyp != NULL);

	if (dst_supported_algorithm(alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	*keyp = get_key_struct(name, alg, flags, protocol, bits, mctx);
	if (*keyp == NULL)
		return (ISC_R_NOMEMORY);

	if (bits == 0) { /* NULL KEY */
		(*keyp)->key_flags |= DNS_KEYTYPE_NOKEY;
		return (ISC_R_SUCCESS);
	}

	ret = (*keyp)->func->generate(*keyp, exp, mctx);
	if (ret != ISC_R_SUCCESS) {
		dst_key_free(*keyp);
		return (ret);
	}

	return (ISC_R_SUCCESS);
}

/*
 *  dst_key_compare
 *	Compares two keys for equality.
 *  Parameters
 *	key1, key2	Two keys to be compared.
 *  Returns
 *	ISC_TRUE	The keys are equal.
 *	ISC_FALSE	The keys are not equal.
 */
isc_boolean_t
dst_key_compare(const dst_key_t *key1, const dst_key_t *key2) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key1));
	REQUIRE(VALID_KEY(key2));

	if (key1 == key2)
		return (ISC_TRUE);
	if (key1 == NULL || key2 == NULL)
		return (ISC_FALSE);
	if (key1->key_alg == key2->key_alg &&
	    key1->key_id == key2->key_id &&
	    key1->func->compare(key1, key2) == ISC_TRUE)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}
/*
 *  dst_key_paramcompare
 *	Compares two keys' parameters for equality.  This is designed to
 *	determine if two (Diffie-Hellman) keys can be used to derive a shared
 *	secret.
 *  Parameters
 *	key1, key2	Two keys whose parameters are to be compared.
 *  Returns
 *	ISC_TRUE	The keys' parameters are equal.
 *	ISC_FALSE	The keys' parameters are not equal.
 */
isc_boolean_t
dst_key_paramcompare(const dst_key_t *key1, const dst_key_t *key2) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key1));
	REQUIRE(VALID_KEY(key2));

	if (key1 == key2)
		return (ISC_TRUE);
	if (key1 == NULL || key2 == NULL)
		return (ISC_FALSE);
	if (key1->key_alg == key2->key_alg &&
	    key1->func->paramcompare != NULL &&
	    key1->func->paramcompare(key1, key2) == ISC_TRUE)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}

/*
 *  dst_key_free
 *	Release all data structures pointed to by a key structure.
 *  Parameters
 *	key	Key structure to be freed.
 */
void
dst_key_free(dst_key_t *key) {
	isc_mem_t *mctx;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));

	mctx = key->mctx;

	if (key->opaque != NULL)
		key->func->destroy(key->opaque, mctx);

	isc_mem_free(mctx, key->key_name);
	memset(key, 0, sizeof(dst_key_t));
	isc_mem_put(mctx, key, sizeof(dst_key_t));
}

char *
dst_key_name(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_name);
}

int
dst_key_size(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_size);
}

int
dst_key_proto(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_proto);
}

int
dst_key_alg(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_alg);
}

isc_uint32_t
dst_key_flags(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_flags);
}

isc_uint16_t
dst_key_id(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_id);
}

isc_boolean_t
dst_key_isprivate(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->func->isprivate(key));
}

/*
 * dst_sig_size
 *	Computes the maximum size of a signature generated by the given key
 * Parameters
 *	key	The DST key
 *	n 	Stores the number of bytes necessary to hold a signature
 *		with the key.
 * Returns
 *	ISC_R_SUCCESS
 *	DST_R_UNSUPPORTEDALG
 */
isc_result_t
dst_sig_size(const dst_key_t *key, unsigned int *n) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(n != NULL);

	switch (key->key_alg) {
		case DST_ALG_RSA:
			*n = (key->key_size + 7) / 8;
			break;
		case DST_ALG_DSA:
			*n = DNS_SIG_DSASIGSIZE;
			break;
		case DST_ALG_HMACMD5:
			*n = 16;
			break;
		case DST_ALG_HMACSHA1:
			*n = 20;
			break;
		case DST_ALG_DH:
		default:
			return (DST_R_UNSUPPORTEDALG);
	}
	return (ISC_R_SUCCESS);
}

/*
 * dst_secret_size
 *	Computes the maximum size of a shared secret generated by the given key
 * Parameters
 *	key	The DST key
 *	n 	Stores the number of bytes necessary to hold a shared secret
 *		generated by the key.
 * Returns
 *	ISC_R_SUCCESS
 *	DST_R_UNSUPPORTEDALG
 */
isc_result_t
dst_secret_size(const dst_key_t *key, unsigned int *n) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(n != NULL);

	switch (key->key_alg) {
		case DST_ALG_DH:
			*n = (key->key_size + 7) / 8;
			break;
		case DST_ALG_RSA:
		case DST_ALG_DSA:
		case DST_ALG_HMACMD5:
		case DST_ALG_HMACSHA1:
		default:
			return (DST_R_UNSUPPORTEDALG);
	}
	return (ISC_R_SUCCESS);
}

/* 
 * dst_random_get
 *	a random number generator that can generate different levels of
 *	randomness
 * Parameters  
 *	mode		selects the random number generator
 *	wanted		the number of random bytes requested 
 *	target		the buffer to store the random data
 * Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
dst_result_t 
dst_random_get(const unsigned int wanted, isc_buffer_t *target) {
	isc_region_t r;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(target != NULL);

	isc_buffer_available(target, &r);
	if (r.length < wanted)
		return (ISC_R_NOSPACE);

	RUNTIME_CHECK(isc_mutex_lock((&random_lock)) == ISC_R_SUCCESS);
	RAND_bytes(r.base, wanted);
	RUNTIME_CHECK(isc_mutex_unlock((&random_lock)) == ISC_R_SUCCESS);
	isc_buffer_add(target, wanted);
	return (ISC_R_SUCCESS);
}

/***
 *** Static methods
 ***/

/*
 *  initialize
 *	This function initializes the Digital Signature Toolkit.
 *  Parameters
 *	none
 *  Returns
 *	none
 */
static void
initialize() {
	memset(dst_t_func, 0, sizeof(dst_t_func));

	RUNTIME_CHECK(isc_mem_create(0, 0, &dst_memory_pool) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_init(&random_lock) == ISC_R_SUCCESS);

	dst_result_register();

	dst_s_hmacmd5_init();
#if defined(BSAFE) || defined(DNSSAFE)
	dst_s_bsafersa_init();
#endif
#ifdef OPENSSL
	dst_s_openssldsa_init();
	dst_s_openssldh_init();
#endif
}

/* 
 * get_key_struct 
 *	This function allocates key structure and fills in some of the 
 *	fields of the structure. 
 * Parameters: 
 *	name		the name of the key 
 *	alg		the algorithm number 
 *	flags		the dns flags of the key
 *	protocol	the dns protocol of the key
 *	bits		the size of the key
 *	mctx		the memory context to allocate from
 * Returns:
 *	NULL		error
 *	valid pointer	otherwise
 */
static dst_key_t *
get_key_struct(const char *name, const int alg, const int flags,
	       const int protocol, const int bits, isc_mem_t *mctx)
{
	dst_key_t *key; 

	REQUIRE(dst_supported_algorithm(alg) != ISC_FALSE);

	key = (dst_key_t *) isc_mem_get(mctx, sizeof(dst_key_t));
	if (key == NULL)
		return (NULL);

	memset(key, 0, sizeof(dst_key_t));
	key->magic = KEY_MAGIC;
	if (name[strlen(name) - 1] == '.') {
		key->key_name = isc_mem_strdup(mctx, name);
		if (key->key_name == NULL) {
			isc_mem_free(mctx, key);
			return (NULL);
		}
	}
	else {
		key->key_name = isc_mem_allocate(mctx, strlen(name) + 2);
		if (key->key_name == NULL) {
			isc_mem_free(mctx, key);
			return (NULL);
		}
		sprintf(key->key_name, "%s.", name);
	}
	key->key_alg = alg;
	key->key_flags = flags;
	key->key_proto = protocol;
	key->mctx = mctx;
	key->opaque = NULL;
	key->key_size = bits;
	key->func = dst_t_func[alg];
	return (key);
}

/*
 *  dst_read_public_key
 *	Read a public key from disk
 *  Parameters
 *	name		The name
 *	id		The id
 *	alg		The algorithm
 *	mctx		The memory context used to allocate the key
 *	keyp		Returns the new key
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static dst_result_t
read_public_key(const char *name, const isc_uint16_t id, int alg,
		      isc_mem_t *mctx, dst_key_t **keyp)
{
	char filename[ISC_DIR_NAMEMAX];
	u_char rdatabuf[DST_KEY_MAXSIZE];
	isc_buffer_t b;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	isc_result_t ret;
	dns_rdata_t rdata;
	unsigned int opt = ISC_LEXOPT_DNSMULTILINE;

	if (dst_s_build_filename(filename, name, id, alg, PUBLIC_KEY,
				 sizeof(filename)) != ISC_R_SUCCESS)
		return (DST_R_NAMETOOLONG);

	/*
	 * Open the file and read its formatted contents
	 * File format:
	 *    domain.name [ttl] [IN] KEY  <flags> <protocol> <algorithm> <key>
	 */

	/* 1500 should be large enough for any key */
	ret = isc_lex_create(mctx, 1500, &lex);
	if (ret != ISC_R_SUCCESS)
		return (ISC_R_NOMEMORY);

	ret = isc_lex_openfile(lex, filename);
	if (ret != ISC_R_SUCCESS) {
		if (ret == ISC_R_FAILURE)
			ret = ISC_R_NOTFOUND;
		goto cleanup;
	}

#define NEXTTOKEN(lex, opt, token) { \
	ret = isc_lex_gettoken(lex, opt, token); \
	if (ret != ISC_R_SUCCESS) \
		goto cleanup; \
	}

	/* Read the domain name */
	NEXTTOKEN(lex, opt, &token);
	
	/* Read the next word: either TTL, 'IN', or 'KEY' */
	NEXTTOKEN(lex, opt, &token);

	/* If it's a TTL, read the next one */
	if (token.type == isc_tokentype_number)
		NEXTTOKEN(lex, opt, &token);
	
	if (token.type != isc_tokentype_string)
		goto cleanup;

	if (strcasecmp(token.value.as_pointer, "IN") == 0)
		NEXTTOKEN(lex, opt, &token);
	
	if (token.type != isc_tokentype_string)
		goto cleanup;

	if (strcasecmp(token.value.as_pointer, "KEY") != 0)
		goto cleanup;
	
	isc_buffer_init(&b, rdatabuf, sizeof(rdatabuf), ISC_BUFFERTYPE_BINARY);
	ret = dns_rdata_fromtext(&rdata, dns_rdataclass_in, dns_rdatatype_key,
				 lex, NULL, ISC_FALSE, &b, NULL);
	if (ret != ISC_R_SUCCESS)
		goto cleanup;

	ret = dst_key_fromdns(name, &b, mctx, keyp);
	if (ret != ISC_R_SUCCESS || (*keyp)->key_alg != alg)
		goto cleanup;

	isc_lex_close(lex);
	isc_lex_destroy(&lex);

	return (ISC_R_SUCCESS);

cleanup:
        if (lex != NULL) {
		isc_lex_close(lex);
		isc_lex_destroy(&lex);
        }
	return (ret);
}


/*
 *  write_public_key
 *	Write a key to disk in DNS format.
 *  Parameters
 *	key		A DST key
 *  Returns
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */

static dst_result_t
write_public_key(const dst_key_t *key) {
	FILE *fp;
	isc_buffer_t keyb, textb;
	isc_region_t r;
	char filename[ISC_DIR_NAMEMAX];
	unsigned char key_array[DST_KEY_MAXSIZE];
	char text_array[DST_KEY_MAXSIZE];
	dst_result_t ret;
	dns_result_t dnsret;
	dns_rdata_t rdata;

	REQUIRE(VALID_KEY(key));

	isc_buffer_init(&keyb, key_array, sizeof(key_array),
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_init(&textb, text_array, sizeof(text_array),
			ISC_BUFFERTYPE_TEXT);

	ret = dst_key_todns(key, &keyb);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	isc_buffer_used(&keyb, &r);
	dns_rdata_fromregion(&rdata, dns_rdataclass_in, dns_rdatatype_key, &r);

	dnsret = dns_rdata_totext(&rdata, (dns_name_t *) NULL, &textb);
	if (dnsret != ISC_R_SUCCESS)
		return (DST_R_INVALIDPUBLICKEY);

	dns_rdata_freestruct(&rdata);

	isc_buffer_used(&textb, &r);
	
	/*
	 * Make the filename.
	 */
	if (dst_s_build_filename(filename,
				 key->key_name, key->key_id, key->key_alg,
				 PUBLIC_KEY, sizeof(filename)) < 0)
		return (DST_R_NAMETOOLONG);

	/*
	 * Create public key file.
	 */
	if ((fp = fopen(filename, "w")) == NULL)
		return (DST_R_WRITEERROR);

	fprintf(fp, "%s IN KEY ", key->key_name);
	fwrite(r.base, 1, r.length, fp);
	fputc('\n', fp);
	fclose(fp);
	return (ISC_R_SUCCESS);
}

void *
dst_mem_alloc(size_t size) {
	INSIST(dst_memory_pool != NULL);
	return (isc_mem_allocate(dst_memory_pool, size));
}

void
dst_mem_free(void *ptr) {
	INSIST(dst_memory_pool != NULL);
	if (ptr != NULL)
		isc_mem_free(dst_memory_pool, ptr);
}

void *
dst_mem_realloc(void *ptr, size_t size) {
	void *p;

	INSIST(dst_memory_pool != NULL);
	p = NULL;
	if (size > 0) {
		p = dst_mem_alloc(size);
		if (p != NULL && ptr != NULL)
			memcpy(p, ptr, size);
	}
	if (ptr != NULL)
		dst_mem_free(ptr);
	return (p);
}
