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

#ifndef ISC_RWLOCK_H
#define ISC_RWLOCK_H 1

#include <inttypes.h>

/*! \file isc/rwlock.h */

#include <isc/atomic.h>
#include <isc/condition.h>
#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

typedef enum {
	isc_rwlocktype_none = 0,
	isc_rwlocktype_read,
	isc_rwlocktype_write
} isc_rwlocktype_t;

#if USE_C_RW_WP
#include <isc/align.h>

#define ISC_RWLOCK_UNLOCKED false
#define ISC_RWLOCK_LOCKED   true

#define ISC_CACHE_LINE	      64 /* TODO: Move to platform.h */
#define ISC_RWLOCK_HASH_RATIO 3
#define ISC_RWLOCK_COUNTERS_RATIO \
	(ISC_RWLOCK_HASH_RATIO * ISC_CACHE_LINE / sizeof(atomic_int_fast32_t))

struct isc_rwlock {
	unsigned int	     magic;
	uint16_t	     hashbits;
	uint16_t	     ncounters;
	alignas(ISC_CACHE_LINE) atomic_int_fast32_t *readers_counters;
	alignas(ISC_CACHE_LINE) atomic_bool writers_mutex;
	alignas(ISC_CACHE_LINE) atomic_int_fast32_t writers_barrier;
};

#elif USE_PTHREAD_RWLOCK
#include <pthread.h>

struct isc_rwlock {
	pthread_rwlock_t rwlock;
	atomic_bool	 downgrade;
};

#else /* USE_PTHREAD_RWLOCK */

struct isc_rwlock {
	/* Unlocked. */
	unsigned int	     magic;
	isc_mutex_t	     lock;
	atomic_uint_fast32_t spins;

	/*
	 * When some atomic instructions with hardware assistance are
	 * available, rwlock will use those so that concurrent readers do not
	 * interfere with each other through mutex as long as no writers
	 * appear, massively reducing the lock overhead in the typical case.
	 *
	 * The basic algorithm of this approach is the "simple
	 * writer-preference lock" shown in the following URL:
	 * http://www.cs.rochester.edu/u/scott/synchronization/pseudocode/rw.html
	 * but our implementation does not rely on the spin lock unlike the
	 * original algorithm to be more portable as a user space application.
	 */

	/* Read or modified atomically. */
	atomic_int_fast32_t write_requests;
	atomic_int_fast32_t write_completions;
	atomic_int_fast32_t cnt_and_flag;

	/* Locked by lock. */
	isc_condition_t readable;
	isc_condition_t writeable;
	unsigned int	readers_waiting;

	/* Locked by rwlock itself. */
	atomic_uint_fast32_t write_granted;

	/* Unlocked. */
	unsigned int write_quota;
};

#endif /* USE_PTHREAD_RWLOCK */

void
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota);

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl);

void
isc_rwlock_downgrade(isc_rwlock_t *rwl);

void
isc_rwlock_destroy(isc_rwlock_t *rwl);

ISC_LANG_ENDDECLS

#endif /* ISC_RWLOCK_H */
