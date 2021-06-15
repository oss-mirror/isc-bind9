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

#pragma once

#include <inttypes.h>

#include <isc/util.h>

#define GOLDEN_RATIO_32 0x61C88647
#define HASHSIZE(bits)	(UINT64_C(1) << (bits))

#define HASHMAP_INIT_BITS  2U
#define HASHMAP_MIN_BITS   1U
#define HASHMAP_MAX_BITS   32U
#define HASHMAP_OVERCOMMIT 3

#define FIB_32(value, bits)                 \
	(REQUIRE(bits <= HASHMAP_MAX_BITS), \
	 value * GOLDEN_RATIO_32 >> (32 - bits))

#define ISC_HASHNEXT(node) ((node)->hashnext)
#define ISC_HASHVAL(node)  ((node)->hashval)

#define ISC_HASHMAP(type)                    \
	struct {                             \
		isc_mem_t *	mctx;        \
		unsigned int	count;       \
		uint16_t	hashbits;    \
		uint16_t	maxhashbits; \
		dns_rbtnode_t **hashtable;   \
	}

#define ISC_HASHMAP_NODE(type)     \
	struct {                   \
		type *	 hashnext; \
		uint32_t hashval;  \
	}

#define HASHMAP_SIZE(bits) HASHSIZE((bits)) * sizeof(void *)

#define ISC_HASHMAP_INIT(mctx, hashmap)                                 \
	{                                                               \
		size_t __hashmap_size = HASHMAP_SIZE(HASHMAP_MIN_BITS); \
		isc_mem_attach((mctx), &(hashmap).mctx);                \
		(hashmap).hashbits = HASHMAP_MIN_BITS;                  \
		(hashmap).maxhashbits = HASHMAP_MAX_BITS;               \
		(hashmap).hashtable = isc_mem_get((hashmap).mctx,       \
						  __hashmap_size);      \
		memset((hashmap).hashtable, 0, __hashmap_size);         \
	}

#define ISC_HASHMAP_DESTROY(mctx, hashmap)                        \
	{                                                         \
		if ((hashmap).hashtable != NULL) {                \
			size_t __hashmap_size =                   \
				HASHMAP_SIZE((hashmap).hashbits); \
			isc_mem_put(mctx, (hashmap).hashtable,    \
				    __hashmap_size);              \
		}                                                 \
	}

#define ISC_HASHMAP_GET(hashmap, key) \
	(hashmap).hashtable[FIB_32(key, (hashmap).hashbits)]

/*
 * Insert the value without rehashing
 */
#define ISC__HASHMAP_INSERT(hashmap, key, node)                                \
	{                                                                      \
		uint32_t hash = FIB_32(ISC_HASHVAL(node), (hashmap).hashbits); \
		ISC_HASHNEXT(node) = (hashmap).hashtable[hash];                \
		(hashmap).hashtable[hash] = node;                              \
	}

/*
 * Rebuild the hashtable to reduce the load factor
 */
#define ISC__HASHMAP_REHASH(hashmap, newbits, type)                           \
	{                                                                     \
		uint32_t oldbits;                                             \
		size_t	 oldsize;                                             \
		type **	 oldtable;                                            \
		size_t	 newsize;                                             \
                                                                              \
		REQUIRE((hashmap).hashbits <= (hashmap).maxhashbits);         \
		REQUIRE(newbits <= (hashmap).maxhashbits);                    \
                                                                              \
		oldbits = (hashmap).hashbits;                                 \
		oldsize = HASHSIZE(oldbits);                                  \
		oldtable = (hashmap).hashtable;                               \
                                                                              \
		(hashmap).hashbits = newbits;                                 \
		newsize = HASHSIZE((hashmap).hashbits);                       \
		(hashmap).hashtable = isc_mem_get((hashmap).mctx,             \
						  newsize * sizeof(type *));  \
		memset((hashmap).hashtable, 0, newsize * sizeof(type *));     \
                                                                              \
		for (size_t i = 0; i < oldsize; i++) {                        \
			type *curnode;                                        \
			type *nextnode;                                       \
			for (curnode = oldtable[i]; curnode != NULL;          \
			     curnode = nextnode) {                            \
				ISC__HASHMAP_INSERT(                          \
					hashmap, ISC_HASHVAL(node), curnode); \
				nextnode = ISC_HASHNEXT(curnode);             \
			}                                                     \
		}                                                             \
                                                                              \
		isc_mem_put((hashmap).mctx, oldtable,                         \
			    oldsize * sizeof(void *));                        \
	}

#define ISC_HASHMAP_PUT(hashmap, node, type)                                 \
	{                                                                    \
		if ((hashmap).count++ >=                                     \
		    (HASHSIZE((hashmap).hashbits) * HASHMAP_OVERCOMMIT)) {   \
			uint32_t newbits = (hashmap).hashbits;               \
			while ((hashmap).count >= HASHSIZE(newbits) &&       \
			       newbits < (hashmap).maxhashbits) {            \
				newbits += 1;                                \
			}                                                    \
			if ((hashmap).hashbits < newbits &&                  \
			    newbits <= (hashmap).maxhashbits) {              \
				ISC__HASHMAP_REHASH(hashmap, newbits, type); \
			}                                                    \
		}                                                            \
		ISC__HASHMAP_INSERT(hashmap, ISC_HASHVAL(node), (node));     \
	}

#define ISC_HASHMAP_DEL(hashmap, node, type)                                   \
	{                                                                      \
		type *	 bucket_node;                                          \
		uint32_t hash = FIB_32(ISC_HASHVAL(node), (hashmap).hashbits); \
                                                                               \
		bucket_node = ISC_HASHMAP_GET(hashmap, ISC_HASHVAL(node));     \
		if (bucket_node == (node)) {                                   \
			(hashmap).hashtable[hash] = ISC_HASHNEXT(node);        \
		} else {                                                       \
			while (ISC_HASHNEXT(bucket_node) != (node)) {          \
				INSIST(ISC_HASHNEXT(bucket_node) != NULL);     \
				bucket_node = ISC_HASHNEXT(bucket_node);       \
			}                                                      \
			ISC_HASHNEXT(bucket_node) = ISC_HASHNEXT(node);        \
		}                                                              \
		(hashmap).count--;                                             \
	}
