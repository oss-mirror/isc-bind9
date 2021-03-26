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

#include <inttypes.h>
#include <linux/futex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/magic.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#if USE_C_RW_WP
/*
 * C-RW-WP Implementation from NUMA-Aware Reader-Writer Locks paper:
 * http://dl.acm.org/citation.cfm?id=2442532
 *
 * This work is based on C++ code available from
 * https://github.com/pramalhe/ConcurrencyFreaks/
 *
 * Copyright (c) 2014-2016, Pedro Ramalhete, Andreia Correia
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Concurrency Freaks nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER>
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#define RWLOCK_MAGIC	  ISC_MAGIC('R', 'W', 'W', 'P')
#define VALID_RWLOCK(rwl) ISC_MAGIC_VALID(rwl, RWLOCK_MAGIC)

#ifndef RWLOCK_DEFAULT_WRITE_QUOTA
#define RWLOCK_DEFAULT_WRITE_QUOTA 4
#endif /* ifndef RWLOCK_DEFAULT_WRITE_QUOTA */

#include <stdlib.h>

#include <isc/os.h>
#include <isc/pause.h>
#include <isc/thread.h>

/* FIXME: Now used in both rwlock.c and rbt.c */
#define HASHSIZE(bits)	(UINT64_C(1) << (bits))
#define HASH_MAX_BITS	32
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static inline uint32_t
hash_32(uint32_t val, unsigned int bits) {
	REQUIRE(bits <= HASH_MAX_BITS);
	/* High bits are more random. */
	return (val * GOLDEN_RATIO_32 >> (32 - bits));
}

static inline size_t
tid2idx(isc_rwlock_t *rwl) {
	uint32_t tid = hash_32(isc_tid_v, rwl->hashbits);
	uint16_t idx = tid * ISC_RWLOCK_COUNTERS_RATIO;

	return (idx);
}

#ifndef RWLOCK_MAX_READER_PATIENCE
#define RWLOCK_MAX_READER_PATIENCE 10
#endif /* ifndef RWLOCK_MAX_READER_PATIENCE */

static inline void
isc__rwlock_exclusive_unlock(isc_rwlock_t *rwl);

static inline isc_result_t
isc__rwlock_check_for_running_readers(isc_rwlock_t *rwl);

static inline void
isc__rwlock_wait_for_running_readers(isc_rwlock_t *rwl);

static int
futex(uint32_t *uaddr, int futex_op, uint32_t val) {
	return syscall(SYS_futex, uaddr, futex_op, val, NULL, NULL, 0);
}

static inline void
isc__rwlock_shared_lock(isc_rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);
	uint32_t cnt = 0;
	bool barrier_raised = false;

	while (true) {
		(void)atomic_fetch_add_release(&rwl->readers_counters[idx], 1);
		if (atomic_load_acquire(&rwl->writers_futex) ==
		    ISC_RWLOCK_UNLOCKED) {
			/* Acquired lock in read-only mode */

			break;
		}

		/* Writer has acquired the lock, must reset to 0 and wait */
		(void)atomic_fetch_sub_release(&rwl->readers_counters[idx], 1);

		long s = futex((uint32_t *)&rwl->writers_futex, FUTEX_WAIT,
			       ISC_RWLOCK_LOCKED);
		INSIST(s != -1 || errno == EAGAIN);

		if (!barrier_raised) {
			if (ISC_UNLIKELY(cnt++ >= RWLOCK_MAX_READER_PATIENCE)) {
				(void)atomic_fetch_add_release(
					&rwl->writers_barrier, 1);
				barrier_raised = true;
			}
		}
	}
	if (barrier_raised) {
		uint32_t old = atomic_fetch_sub_release(&rwl->writers_barrier,
							1);
		if (old == 1) {
			long s = futex((uint32_t *)&rwl->writers_barrier,
				       FUTEX_WAKE, INT_MAX);
			INSIST(s != -1);
		}
	}
}

static inline isc_result_t
isc__rwlock_shared_trylock(isc_rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);

	(void)atomic_fetch_add_release(&rwl->readers_counters[idx], 1);
	if (atomic_load_acquire(&rwl->writers_futex) == ISC_RWLOCK_LOCKED) {
		/* Writer has acquired the lock, must reset to 0 */
		(void)atomic_fetch_sub_release(&rwl->readers_counters[idx], 1);

		return (ISC_R_LOCKBUSY);
	}

	/* Acquired lock in read-only mode */
	return (ISC_R_SUCCESS);
}

static inline void
isc__rwlock_shared_unlock(isc_rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);
	REQUIRE(atomic_fetch_sub_release(&rwl->readers_counters[idx], 1) > 0);
}

static inline isc_result_t
isc__rwlock_shared_tryupgrade(isc_rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);

	/* Write Barriers has been raised */
	if (atomic_load_acquire(&rwl->writers_barrier) > 0) {
		return (ISC_R_LOCKBUSY);
	}

	/* Try to acquire the write-lock */
	if (!atomic_compare_exchange_weak_acq_rel(
		    &rwl->writers_futex, &(uint32_t){ ISC_RWLOCK_UNLOCKED },
		    ISC_RWLOCK_LOCKED))
	{
		return (ISC_R_LOCKBUSY);
	}

	/* Unlock the read-lock */
	REQUIRE(atomic_fetch_sub_release(&rwl->readers_counters[idx], 1) > 0);

	if (isc__rwlock_check_for_running_readers(rwl) == ISC_R_LOCKBUSY) {
		/* Re-acquire the read-lock back */
		(void)atomic_fetch_add_release(&rwl->readers_counters[idx], 1);

		/* Unlock the write-lock */
		isc__rwlock_exclusive_unlock(rwl);
		return (ISC_R_LOCKBUSY);
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
isc__rwlock_check_for_running_readers(isc_rwlock_t *rwl) {
	/* Write-lock was acquired, now wait for running Readers to finish */
	for (size_t idx = 0; idx < rwl->ncounters;
	     idx += ISC_RWLOCK_COUNTERS_RATIO) {
		if (atomic_load_relaxed(&rwl->readers_counters[idx]) > 0) {
			return (ISC_R_LOCKBUSY);
		}
	}

	return (ISC_R_SUCCESS);
}

static inline void
isc__rwlock_wait_for_running_readers(isc_rwlock_t *rwl) {
	/* Write-lock was acquired, now wait for running Readers to finish */
	for (size_t idx = 0; idx < rwl->ncounters;
	     idx += ISC_RWLOCK_COUNTERS_RATIO) {
		while (atomic_load_acquire(&rwl->readers_counters[idx]) > 0) {
			isc_pause(1);
		}
	}
}

static inline void
isc__rwlock_exclusive_lock(isc_rwlock_t *rwl) {
	/* Write Barriers has been raised, wait */
	while (true) {
		uint32_t old = atomic_load_acquire(&rwl->writers_barrier);
		if (old == 0) {
			break;
		}

		long s = futex((uint32_t *)&rwl->writers_barrier, FUTEX_WAIT,
			       old);
		INSIST(s != -1 || errno == EAGAIN);
	}

	while (true) {
		if (atomic_compare_exchange_weak_acq_rel(
			    &rwl->writers_futex,
			    &(uint32_t){ ISC_RWLOCK_UNLOCKED },
			    ISC_RWLOCK_LOCKED))
		{
			break;
		}

		long s = futex((uint32_t *)&rwl->writers_futex, FUTEX_WAIT,
			       ISC_RWLOCK_LOCKED);
		INSIST(s != -1 || errno == EAGAIN);
	}

	isc__rwlock_wait_for_running_readers(rwl);
}

static isc_result_t
isc__rwlock_exclusive_trylock(isc_rwlock_t *rwl) {
	/* Write Barriers has been raised */
	if (atomic_load_acquire(&rwl->writers_barrier) > 0) {
		return (ISC_R_LOCKBUSY);
	}

	/* Try to acquire the write-lock */
	if (!atomic_compare_exchange_weak_acq_rel(
		    &rwl->writers_futex, &(uint32_t){ ISC_RWLOCK_UNLOCKED },
		    ISC_RWLOCK_LOCKED))
	{
		return (ISC_R_LOCKBUSY);
	}

	if (isc__rwlock_check_for_running_readers(rwl)) {
		/* Unlock the write-lock */
		isc__rwlock_exclusive_unlock(rwl);

		return (ISC_R_LOCKBUSY);
	}

	return (ISC_R_SUCCESS);
}

static inline void
isc__rwlock_exclusive_unlock(isc_rwlock_t *rwl) {
	REQUIRE(atomic_compare_exchange_strong_acq_rel(
		&rwl->writers_futex, &(uint32_t){ ISC_RWLOCK_LOCKED },
		ISC_RWLOCK_UNLOCKED));
	long s = futex((uint32_t *)&rwl->writers_futex, FUTEX_WAKE, INT_MAX);
	INSIST(s != -1);
}

static inline void
isc__rwlock_exclusive_downgrade(isc_rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);

	(void)atomic_fetch_add_release(&rwl->readers_counters[idx], 1);

	isc__rwlock_exclusive_unlock(rwl);
}

void
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota) {
	uint16_t ncpus = isc_os_ncpus();

	REQUIRE(rwl != NULL);
	rwl->magic = 0;
	rwl->hashbits = 0;

	if (read_quota != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "read quota is not supported");
	}
	if (write_quota != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "write quota is not supported");
	}

	while (ncpus > HASHSIZE(rwl->hashbits)) {
		rwl->hashbits += 1;
	}
	RUNTIME_CHECK(rwl->hashbits <= HASH_MAX_BITS);
	rwl->ncounters = HASHSIZE(rwl->hashbits) * ISC_RWLOCK_COUNTERS_RATIO;
	atomic_init(&rwl->writers_futex, ISC_RWLOCK_UNLOCKED);
	atomic_init(&rwl->writers_barrier, 0);
	rwl->readers_counters =
		malloc(rwl->ncounters * sizeof(rwl->readers_counters[0]));
	for (size_t i = 0; i < rwl->ncounters; i++) {
		atomic_init(&rwl->readers_counters[i], 0);
	}
	rwl->magic = RWLOCK_MAGIC;
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));
	rwl->magic = 0;

	/* Check whether write lock has been unlocked */
	REQUIRE(atomic_load(&rwl->writers_futex) == ISC_RWLOCK_UNLOCKED);

	/* Check whether all read locks has been unlocked */
	for (size_t i = 0; i < rwl->ncounters; i++) {
		REQUIRE(atomic_load(&rwl->readers_counters[i]) == 0);
	}

	free(rwl->readers_counters);
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (type) {
	case isc_rwlocktype_read:
		isc__rwlock_shared_lock(rwl);
		break;
	case isc_rwlocktype_write:
		isc__rwlock_exclusive_lock(rwl);
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (type) {
	case isc_rwlocktype_read:
		return (isc__rwlock_shared_trylock(rwl));
		break;
	case isc_rwlocktype_write:
		return (isc__rwlock_exclusive_trylock(rwl));
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (type) {
	case isc_rwlocktype_read:
		isc__rwlock_shared_unlock(rwl);
		break;
	case isc_rwlocktype_write:
		isc__rwlock_exclusive_unlock(rwl);
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl) {
	return (isc__rwlock_shared_tryupgrade(rwl));
}

void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {
	isc__rwlock_exclusive_downgrade(rwl);
}

#elif USE_PTHREAD_RWLOCK

#include <errno.h>
#include <pthread.h>

void
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota) {
	UNUSED(read_quota);
	UNUSED(write_quota);
	REQUIRE(pthread_rwlock_init(&rwl->rwlock, NULL) == 0);
	atomic_init(&rwl->downgrade, false);
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	switch (type) {
	case isc_rwlocktype_read:
		REQUIRE(pthread_rwlock_rdlock(&rwl->rwlock) == 0);
		break;
	case isc_rwlocktype_write:
		while (true) {
			REQUIRE(pthread_rwlock_wrlock(&rwl->rwlock) == 0);
			/* Unlock if in middle of downgrade operation */
			if (atomic_load_acquire(&rwl->downgrade)) {
				REQUIRE(pthread_rwlock_unlock(&rwl->rwlock) ==
					0);
				while (atomic_load_acquire(&rwl->downgrade)) {
				}
				continue;
			}
			break;
		}
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	int ret = 0;
	switch (type) {
	case isc_rwlocktype_read:
		ret = pthread_rwlock_tryrdlock(&rwl->rwlock);
		break;
	case isc_rwlocktype_write:
		ret = pthread_rwlock_trywrlock(&rwl->rwlock);
		if ((ret == 0) && atomic_load_acquire(&rwl->downgrade)) {
			isc_rwlock_unlock(rwl, type);
			return (ISC_R_LOCKBUSY);
		}
		break;
	default:
		INSIST(0);
	}

	switch (ret) {
	case 0:
		return (ISC_R_SUCCESS);
	case EBUSY:
		return (ISC_R_LOCKBUSY);
	case EAGAIN:
		return (ISC_R_LOCKBUSY);
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	UNUSED(type);
	REQUIRE(pthread_rwlock_unlock(&rwl->rwlock) == 0);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl) {
	UNUSED(rwl);
	return (ISC_R_LOCKBUSY);
}

void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {
	atomic_store_release(&rwl->downgrade, true);
	isc_rwlock_unlock(rwl, isc_rwlocktype_write);
	isc_rwlock_lock(rwl, isc_rwlocktype_read);
	atomic_store_release(&rwl->downgrade, false);
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	pthread_rwlock_destroy(&rwl->rwlock);
}

#else /* if USE_PTHREAD_RWLOCK */

#define RWLOCK_MAGIC	  ISC_MAGIC('R', 'W', 'L', 'k')
#define VALID_RWLOCK(rwl) ISC_MAGIC_VALID(rwl, RWLOCK_MAGIC)

#ifndef RWLOCK_DEFAULT_READ_QUOTA
#define RWLOCK_DEFAULT_READ_QUOTA 4
#endif /* ifndef RWLOCK_DEFAULT_READ_QUOTA */

#ifndef RWLOCK_DEFAULT_WRITE_QUOTA
#define RWLOCK_DEFAULT_WRITE_QUOTA 4
#endif /* ifndef RWLOCK_DEFAULT_WRITE_QUOTA */

#ifndef RWLOCK_MAX_ADAPTIVE_COUNT
#define RWLOCK_MAX_ADAPTIVE_COUNT 2000
#endif /* ifndef RWLOCK_MAX_ADAPTIVE_COUNT */

static isc_result_t
isc__rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

#ifdef ISC_RWLOCK_TRACE
#include <stdio.h> /* Required for fprintf/stderr. */

#include <isc/thread.h> /* Required for isc_thread_self(). */

static void
print_lock(const char *operation, isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	fprintf(stderr,
		"rwlock %p thread %" PRIuPTR " %s(%s): "
		"write_requests=%u, write_completions=%u, "
		"cnt_and_flag=0x%x, readers_waiting=%u, "
		"write_granted=%u, write_quota=%u\n",
		rwl, isc_thread_self(), operation,
		(type == isc_rwlocktype_read ? "read" : "write"),
		atomic_load_acquire(&rwl->write_requests),
		atomic_load_acquire(&rwl->write_completions),
		atomic_load_acquire(&rwl->cnt_and_flag), rwl->readers_waiting,
		atomic_load_acquire(&rwl->write_granted), rwl->write_quota);
}
#endif			/* ISC_RWLOCK_TRACE */

void
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota) {
	REQUIRE(rwl != NULL);

	/*
	 * In case there's trouble initializing, we zero magic now.  If all
	 * goes well, we'll set it to RWLOCK_MAGIC.
	 */
	rwl->magic = 0;

	atomic_init(&rwl->spins, 0);
	atomic_init(&rwl->write_requests, 0);
	atomic_init(&rwl->write_completions, 0);
	atomic_init(&rwl->cnt_and_flag, 0);
	rwl->readers_waiting = 0;
	atomic_init(&rwl->write_granted, 0);
	if (read_quota != 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "read quota is not supported");
	}
	if (write_quota == 0) {
		write_quota = RWLOCK_DEFAULT_WRITE_QUOTA;
	}
	rwl->write_quota = write_quota;

	isc_mutex_init(&rwl->lock);

	isc_condition_init(&rwl->readable);
	isc_condition_init(&rwl->writeable);

	rwl->magic = RWLOCK_MAGIC;
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	REQUIRE(atomic_load_acquire(&rwl->write_requests) ==
			atomic_load_acquire(&rwl->write_completions) &&
		atomic_load_acquire(&rwl->cnt_and_flag) == 0 &&
		rwl->readers_waiting == 0);

	rwl->magic = 0;
	(void)isc_condition_destroy(&rwl->readable);
	(void)isc_condition_destroy(&rwl->writeable);
	isc_mutex_destroy(&rwl->lock);
}

/*
 * When some architecture-dependent atomic operations are available,
 * rwlock can be more efficient than the generic algorithm defined below.
 * The basic algorithm is described in the following URL:
 *   http://www.cs.rochester.edu/u/scott/synchronization/pseudocode/rw.html
 *
 * The key is to use the following integer variables modified atomically:
 *   write_requests, write_completions, and cnt_and_flag.
 *
 * write_requests and write_completions act as a waiting queue for writers
 * in order to ensure the FIFO order.  Both variables begin with the initial
 * value of 0.  When a new writer tries to get a write lock, it increments
 * write_requests and gets the previous value of the variable as a "ticket".
 * When write_completions reaches the ticket number, the new writer can start
 * writing.  When the writer completes its work, it increments
 * write_completions so that another new writer can start working.  If the
 * write_requests is not equal to write_completions, it means a writer is now
 * working or waiting.  In this case, a new readers cannot start reading, or
 * in other words, this algorithm basically prefers writers.
 *
 * cnt_and_flag is a "lock" shared by all readers and writers.  This integer
 * variable is a kind of structure with two members: writer_flag (1 bit) and
 * reader_count (31 bits).  The writer_flag shows whether a writer is working,
 * and the reader_count shows the number of readers currently working or almost
 * ready for working.  A writer who has the current "ticket" tries to get the
 * lock by exclusively setting the writer_flag to 1, provided that the whole
 * 32-bit is 0 (meaning no readers or writers working).  On the other hand,
 * a new reader tries to increment the "reader_count" field provided that
 * the writer_flag is 0 (meaning there is no writer working).
 *
 * If some of the above operations fail, the reader or the writer sleeps
 * until the related condition changes.  When a working reader or writer
 * completes its work, some readers or writers are sleeping, and the condition
 * that suspended the reader or writer has changed, it wakes up the sleeping
 * readers or writers.
 *
 * As already noted, this algorithm basically prefers writers.  In order to
 * prevent readers from starving, however, the algorithm also introduces the
 * "writer quota" (Q).  When Q consecutive writers have completed their work,
 * suspending readers, the last writer will wake up the readers, even if a new
 * writer is waiting.
 *
 * Implementation specific note: due to the combination of atomic operations
 * and a mutex lock, ordering between the atomic operation and locks can be
 * very sensitive in some cases.  In particular, it is generally very important
 * to check the atomic variable that requires a reader or writer to sleep after
 * locking the mutex and before actually sleeping; otherwise, it could be very
 * likely to cause a deadlock.  For example, assume "var" is a variable
 * atomically modified, then the corresponding code would be:
 *	if (var == need_sleep) {
 *		LOCK(lock);
 *		if (var == need_sleep)
 *			WAIT(cond, lock);
 *		UNLOCK(lock);
 *	}
 * The second check is important, since "var" is protected by the atomic
 * operation, not by the mutex, and can be changed just before sleeping.
 * (The first "if" could be omitted, but this is also important in order to
 * make the code efficient by avoiding the use of the mutex unless it is
 * really necessary.)
 */

#define WRITER_ACTIVE 0x1
#define READER_INCR   0x2

static isc_result_t
isc__rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	int32_t cntflag;

	REQUIRE(VALID_RWLOCK(rwl));

#ifdef ISC_RWLOCK_TRACE
	print_lock("prelock", rwl, type);
#endif /* ifdef ISC_RWLOCK_TRACE */

	if (type == isc_rwlocktype_read) {
		if (atomic_load_acquire(&rwl->write_requests) !=
		    atomic_load_acquire(&rwl->write_completions))
		{
			/* there is a waiting or active writer */
			LOCK(&rwl->lock);
			if (atomic_load_acquire(&rwl->write_requests) !=
			    atomic_load_acquire(&rwl->write_completions))
			{
				rwl->readers_waiting++;
				WAIT(&rwl->readable, &rwl->lock);
				rwl->readers_waiting--;
			}
			UNLOCK(&rwl->lock);
		}

		cntflag = atomic_fetch_add_release(&rwl->cnt_and_flag,
						   READER_INCR);
		POST(cntflag);
		while (1) {
			if ((atomic_load_acquire(&rwl->cnt_and_flag) &
			     WRITER_ACTIVE) == 0) {
				break;
			}

			/* A writer is still working */
			LOCK(&rwl->lock);
			rwl->readers_waiting++;
			if ((atomic_load_acquire(&rwl->cnt_and_flag) &
			     WRITER_ACTIVE) != 0) {
				WAIT(&rwl->readable, &rwl->lock);
			}
			rwl->readers_waiting--;
			UNLOCK(&rwl->lock);

			/*
			 * Typically, the reader should be able to get a lock
			 * at this stage:
			 *   (1) there should have been no pending writer when
			 *       the reader was trying to increment the
			 *       counter; otherwise, the writer should be in
			 *       the waiting queue, preventing the reader from
			 *       proceeding to this point.
			 *   (2) once the reader increments the counter, no
			 *       more writer can get a lock.
			 * Still, it is possible another writer can work at
			 * this point, e.g. in the following scenario:
			 *   A previous writer unlocks the writer lock.
			 *   This reader proceeds to point (1).
			 *   A new writer appears, and gets a new lock before
			 *   the reader increments the counter.
			 *   The reader then increments the counter.
			 *   The previous writer notices there is a waiting
			 *   reader who is almost ready, and wakes it up.
			 * So, the reader needs to confirm whether it can now
			 * read explicitly (thus we loop).  Note that this is
			 * not an infinite process, since the reader has
			 * incremented the counter at this point.
			 */
		}

		/*
		 * If we are temporarily preferred to writers due to the writer
		 * quota, reset the condition (race among readers doesn't
		 * matter).
		 */
		atomic_store_release(&rwl->write_granted, 0);
	} else {
		int32_t prev_writer;

		/* enter the waiting queue, and wait for our turn */
		prev_writer = atomic_fetch_add_release(&rwl->write_requests, 1);
		while (atomic_load_acquire(&rwl->write_completions) !=
		       prev_writer) {
			LOCK(&rwl->lock);
			if (atomic_load_acquire(&rwl->write_completions) !=
			    prev_writer) {
				WAIT(&rwl->writeable, &rwl->lock);
				UNLOCK(&rwl->lock);
				continue;
			}
			UNLOCK(&rwl->lock);
			break;
		}

		while (!atomic_compare_exchange_weak_acq_rel(
			&rwl->cnt_and_flag, &(int_fast32_t){ 0 },
			WRITER_ACTIVE))
		{
			/* Another active reader or writer is working. */
			LOCK(&rwl->lock);
			if (atomic_load_acquire(&rwl->cnt_and_flag) != 0) {
				WAIT(&rwl->writeable, &rwl->lock);
			}
			UNLOCK(&rwl->lock);
		}

		INSIST((atomic_load_acquire(&rwl->cnt_and_flag) &
			WRITER_ACTIVE));
		atomic_fetch_add_release(&rwl->write_granted, 1);
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock("postlock", rwl, type);
#endif /* ifdef ISC_RWLOCK_TRACE */

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	isc_result_t result = ISC_R_SUCCESS;
	uint32_t cnt = 0;
	uint32_t update;
	const uint32_t cachedspins = atomic_load_acquire(&rwl->spins);
	const uint32_t spins = cachedspins * 2 + 10;
	const uint32_t max_cnt = ISC_MIN(spins, RWLOCK_MAX_ADAPTIVE_COUNT);

	while (isc_rwlock_trylock(rwl, type) != ISC_R_SUCCESS) {
		if (ISC_LIKELY(cnt < max_cnt)) {
			cnt++;
			isc_pause(1);
		} else {
			result = isc__rwlock_lock(rwl, type);
			break;
		}
	}
	/*
	 * C99 integer division rounds towards 0, but we want a real 'floor'
	 * here - otherwise we will never drop to anything below 7.
	 */
	update = ((cnt - cachedspins + 9) / 8) - 1;
	atomic_fetch_add_release(&rwl->spins, update);

	return (result);
}

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	int32_t cntflag;

	REQUIRE(VALID_RWLOCK(rwl));

#ifdef ISC_RWLOCK_TRACE
	print_lock("prelock", rwl, type);
#endif /* ifdef ISC_RWLOCK_TRACE */

	if (type == isc_rwlocktype_read) {
		/* If a writer is waiting or working, we fail. */
		if (atomic_load_acquire(&rwl->write_requests) !=
		    atomic_load_acquire(&rwl->write_completions))
		{
			return (ISC_R_LOCKBUSY);
		}

		/* Otherwise, be ready for reading. */
		cntflag = atomic_fetch_add_release(&rwl->cnt_and_flag,
						   READER_INCR);
		if ((cntflag & WRITER_ACTIVE) != 0) {
			/*
			 * A writer is working.  We lose, and cancel the read
			 * request.
			 */
			cntflag = atomic_fetch_sub_release(&rwl->cnt_and_flag,
							   READER_INCR);
			/*
			 * If no other readers are waiting and we've suspended
			 * new writers in this short period, wake them up.
			 */
			if (cntflag == READER_INCR &&
			    atomic_load_acquire(&rwl->write_completions) !=
				    atomic_load_acquire(&rwl->write_requests))
			{
				LOCK(&rwl->lock);
				BROADCAST(&rwl->writeable);
				UNLOCK(&rwl->lock);
			}

			return (ISC_R_LOCKBUSY);
		}
	} else {
		/* Try locking without entering the waiting queue. */
		int_fast32_t zero = 0;
		if (!atomic_compare_exchange_strong_acq_rel(
			    &rwl->cnt_and_flag, &zero, WRITER_ACTIVE))
		{
			return (ISC_R_LOCKBUSY);
		}

		/*
		 * XXXJT: jump into the queue, possibly breaking the writer
		 * order.
		 */
		atomic_fetch_sub_release(&rwl->write_completions, 1);
		atomic_fetch_add_release(&rwl->write_granted, 1);
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock("postlock", rwl, type);
#endif /* ifdef ISC_RWLOCK_TRACE */

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	int_fast32_t reader_incr = READER_INCR;

	/* Try to acquire write access. */
	atomic_compare_exchange_strong_acq_rel(&rwl->cnt_and_flag, &reader_incr,
					       WRITER_ACTIVE);
	/*
	 * There must have been no writer, and there must have
	 * been at least one reader.
	 */
	INSIST((reader_incr & WRITER_ACTIVE) == 0 &&
	       (reader_incr & ~WRITER_ACTIVE) != 0);

	if (reader_incr == READER_INCR) {
		/*
		 * We are the only reader and have been upgraded.
		 * Now jump into the head of the writer waiting queue.
		 */
		atomic_fetch_sub_release(&rwl->write_completions, 1);
	} else {
		return (ISC_R_LOCKBUSY);
	}

	return (ISC_R_SUCCESS);
}

void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {
	int32_t prev_readers;

	REQUIRE(VALID_RWLOCK(rwl));

	/* Become an active reader. */
	prev_readers = atomic_fetch_add_release(&rwl->cnt_and_flag,
						READER_INCR);
	/* We must have been a writer. */
	INSIST((prev_readers & WRITER_ACTIVE) != 0);

	/* Complete write */
	atomic_fetch_sub_release(&rwl->cnt_and_flag, WRITER_ACTIVE);
	atomic_fetch_add_release(&rwl->write_completions, 1);

	/* Resume other readers */
	LOCK(&rwl->lock);
	if (rwl->readers_waiting > 0) {
		BROADCAST(&rwl->readable);
	}
	UNLOCK(&rwl->lock);
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	int32_t prev_cnt;

	REQUIRE(VALID_RWLOCK(rwl));

#ifdef ISC_RWLOCK_TRACE
	print_lock("preunlock", rwl, type);
#endif /* ifdef ISC_RWLOCK_TRACE */

	if (type == isc_rwlocktype_read) {
		prev_cnt = atomic_fetch_sub_release(&rwl->cnt_and_flag,
						    READER_INCR);
		/*
		 * If we're the last reader and any writers are waiting, wake
		 * them up.  We need to wake up all of them to ensure the
		 * FIFO order.
		 */
		if (prev_cnt == READER_INCR &&
		    atomic_load_acquire(&rwl->write_completions) !=
			    atomic_load_acquire(&rwl->write_requests))
		{
			LOCK(&rwl->lock);
			BROADCAST(&rwl->writeable);
			UNLOCK(&rwl->lock);
		}
	} else {
		bool wakeup_writers = true;

		/*
		 * Reset the flag, and (implicitly) tell other writers
		 * we are done.
		 */
		atomic_fetch_sub_release(&rwl->cnt_and_flag, WRITER_ACTIVE);
		atomic_fetch_add_release(&rwl->write_completions, 1);

		if ((atomic_load_acquire(&rwl->write_granted) >=
		     rwl->write_quota) ||
		    (atomic_load_acquire(&rwl->write_requests) ==
		     atomic_load_acquire(&rwl->write_completions)) ||
		    (atomic_load_acquire(&rwl->cnt_and_flag) & ~WRITER_ACTIVE))
		{
			/*
			 * We have passed the write quota, no writer is
			 * waiting, or some readers are almost ready, pending
			 * possible writers.  Note that the last case can
			 * happen even if write_requests != write_completions
			 * (which means a new writer in the queue), so we need
			 * to catch the case explicitly.
			 */
			LOCK(&rwl->lock);
			if (rwl->readers_waiting > 0) {
				wakeup_writers = false;
				BROADCAST(&rwl->readable);
			}
			UNLOCK(&rwl->lock);
		}

		if ((atomic_load_acquire(&rwl->write_requests) !=
		     atomic_load_acquire(&rwl->write_completions)) &&
		    wakeup_writers)
		{
			LOCK(&rwl->lock);
			BROADCAST(&rwl->writeable);
			UNLOCK(&rwl->lock);
		}
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock("postunlock", rwl, type);
#endif /* ifdef ISC_RWLOCK_TRACE */

	return (ISC_R_SUCCESS);
}

#endif /* USE_PTHREAD_RWLOCK */
