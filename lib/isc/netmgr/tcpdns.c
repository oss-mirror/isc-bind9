/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"
#include "uv-compat.h"

#define TCPDNS_CLIENTS_PER_CONN 23
/*%<
 *
 * Maximum number of simultaneous handles in flight supported for a single
 * connected TCPDNS socket. This value was chosen arbitrarily, and may be
 * changed in the future.
 */

static void
dnslisten_readcb(isc_nmhandle_t *handle, isc_result_t eresult,
		 isc_region_t *region, void *arg);

static void
resume_processing(void *arg);

static void
tcpdns_close_direct(isc_nmsocket_t *sock);

static inline size_t
dnslen(unsigned char *base) {
	return ((base[0] << 8) + (base[1]));
}

/*
 * Regular TCP buffer, should suffice in most cases.
 */
#define NM_REG_BUF 4096
/*
 * Two full DNS packets with lengths.
 * netmgr receives 64k at most so there's no risk
 * of overrun.
 */
#define NM_BIG_BUF (65535 + 2) * 2
static inline void
alloc_dnsbuf(isc_nmsocket_t *sock, size_t len) {
	REQUIRE(len <= NM_BIG_BUF);

	if (sock->buf == NULL) {
		/* We don't have the buffer at all */
		size_t alloc_len = len < NM_REG_BUF ? NM_REG_BUF : NM_BIG_BUF;
		sock->buf = isc_mem_allocate(sock->mgr->mctx, alloc_len);
		sock->buf_size = alloc_len;
	} else {
		/* We have the buffer but it's too small */
		sock->buf = isc_mem_reallocate(sock->mgr->mctx, sock->buf,
					       NM_BIG_BUF);
		sock->buf_size = NM_BIG_BUF;
	}
}

static void
timer_close_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)uv_handle_get_data(handle);
	INSIST(VALID_NMSOCK(sock));
	atomic_store(&sock->closed, true);
	tcpdns_close_direct(sock);
}

static void
dnstcp_readtimeout(uv_timer_t *timer) {
	isc_nmsocket_t *sock =
		(isc_nmsocket_t *)uv_handle_get_data((uv_handle_t *)timer);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());
	/* Close the TCP connection, it's closing should fire 'our' closing */
	isc_nmhandle_unref(sock->outerhandle);
	sock->outerhandle = NULL;
}

/*
 * Accept callback for TCP-DNS connection.
 */
static void
dnslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *dnslistensock = (isc_nmsocket_t *)cbarg;
	isc_nmsocket_t *dnssock = NULL;

	REQUIRE(VALID_NMSOCK(dnslistensock));
	REQUIRE(dnslistensock->type == isc_nm_tcpdnslistener);

	/* If accept() was unnsuccessful we can't do anything */
	if (result != ISC_R_SUCCESS) {
		return;
	}

	if (dnslistensock->accept_cb.accept != NULL) {
		dnslistensock->accept_cb.accept(handle, ISC_R_SUCCESS,
						dnslistensock->accept_cbarg);
	}

	/* We need to create a 'wrapper' dnssocket for this connection */
	dnssock = isc_mem_get(handle->sock->mgr->mctx, sizeof(*dnssock));
	isc__nmsocket_init(dnssock, handle->sock->mgr, isc_nm_tcpdnssocket,
			   handle->sock->iface);

	dnssock->extrahandlesize = dnslistensock->extrahandlesize;
	isc__nmsocket_attach(dnslistensock, &dnssock->listener);

	isc__nmsocket_attach(dnssock, &dnssock->self);

	dnssock->outerhandle = handle;
	isc_nmhandle_ref(dnssock->outerhandle);

	dnssock->peer = handle->sock->peer;
	dnssock->read_timeout = handle->sock->mgr->init;
	dnssock->tid = isc_nm_tid();
	dnssock->closehandle_cb = resume_processing;

	uv_timer_init(&dnssock->mgr->workers[isc_nm_tid()].loop,
		      &dnssock->timer);
	dnssock->timer.data = dnssock;
	dnssock->timer_initialized = true;
	uv_timer_start(&dnssock->timer, dnstcp_readtimeout,
		       dnssock->read_timeout, 0);
	isc_nmhandle_ref(handle);
	result = isc_nm_read(handle, dnslisten_readcb, dnssock);
	if (result != ISC_R_SUCCESS) {
		isc_nmhandle_unref(handle);
	}
	isc__nmsocket_detach(&dnssock);
}

/*
 * Process a single packet from the incoming buffer.
 *
 * Return ISC_R_SUCCESS and attach 'handlep' to a handle if something
 * was processed; return ISC_R_NOMORE if there isn't a full message
 * to be processed.
 *
 * The caller will need to unreference the handle.
 */
static isc_result_t
processbuffer(isc_nmsocket_t *dnssock, isc_nmhandle_t **handlep) {
	size_t len;

	REQUIRE(VALID_NMSOCK(dnssock));
	REQUIRE(handlep != NULL && *handlep == NULL);

	/*
	 * If we don't even have the length yet, we can't do
	 * anything.
	 */
	if (dnssock->buf_len < 2) {
		return (ISC_R_NOMORE);
	}
	
	if (dnssock->listener == NULL && dnssock->rcb.recv == NULL) {
		/* Nobody waits for us, pause. */
		return (ISC_R_DISABLED);
	}

	/*
	 * Process the first packet from the buffer, leaving
	 * the rest (if any) for later.
	 */
	len = dnslen(dnssock->buf);
	if (len <= dnssock->buf_len - 2) {
		isc_nmhandle_t *dnshandle;
		if (dnssock->statichandle != NULL) {
			dnshandle = dnssock->statichandle;
			isc_nmhandle_ref(dnshandle);
		} else {
			dnshandle = isc__nmhandle_get(dnssock, NULL, NULL);
		}
		
		isc_nmsocket_t *listener = dnssock->listener;

		if (listener != NULL && listener->rcb.recv != NULL) {
			listener->rcb.recv(
				dnshandle, ISC_R_SUCCESS,
				&(isc_region_t){ .base = dnssock->buf + 2,
						 .length = len },
				listener->rcbarg);
		} else if (dnssock->rcb.recv != NULL) {
			/*
			 * We need to clear the callback before issuing it -
			 * as the callback itself might replace it.
			 */
			isc_nm_recv_cb_t cb = dnssock->rcb.recv;
			void* cbarg = dnssock->rcbarg;
			dnssock->rcb.recv = NULL;
			dnssock->rcbarg = NULL;
			cb(dnshandle, ISC_R_SUCCESS,
			   &(isc_region_t){ .base = dnssock->buf + 2,
					    .length = len },
			   cbarg);
		}

		len += 2;
		dnssock->buf_len -= len;
		if (len > 0) {
			memmove(dnssock->buf, dnssock->buf + len,
				dnssock->buf_len);
		}

		*handlep = dnshandle;
		return (ISC_R_SUCCESS);
	}

	return (ISC_R_NOMORE);
}

/*
 * We've got a read on our underlying socket, need to check if we have
 * a complete DNS packet and, if so - call the callback
 */
static void
dnslisten_readcb(isc_nmhandle_t *handle, isc_result_t eresult,
		 isc_region_t *region, void *arg) {
	isc_nmsocket_t *dnssock = (isc_nmsocket_t *)arg;
	unsigned char *base = NULL;
	bool done = false;
	size_t len;

	REQUIRE(VALID_NMSOCK(dnssock));
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(dnssock->tid == isc_nm_tid());

	if (region == NULL || eresult != ISC_R_SUCCESS) {
		/* Connection closed */
		isc_nmhandle_unref(handle);
		dnssock->result = eresult;
		if (dnssock->self != NULL) {
			isc__nmsocket_detach(&dnssock->self);
		}
		return;
	}

	base = region->base;
	len = region->length;

	if (dnssock->buf_len + len > dnssock->buf_size) {
		alloc_dnsbuf(dnssock, dnssock->buf_len + len);
	}
	memmove(dnssock->buf + dnssock->buf_len, base, len);
	dnssock->buf_len += len;

	dnssock->read_timeout = (atomic_load(&dnssock->keepalive)
					 ? dnssock->mgr->keepalive
					 : dnssock->mgr->idle);

	do {
		isc_result_t result;
		isc_nmhandle_t *dnshandle = NULL;

		result = processbuffer(dnssock, &dnshandle);
		if (result == ISC_R_DISABLED) {
			/*
			 * Nobody is waiting on the callback, pause reading.
			 */
			isc_nm_pauseread(dnssock->outerhandle->sock);
			return;
		} else if (result == ISC_R_NOMORE) {
			/*
			 * There wasn't anything in the buffer to process
			 */
			return;
		}
		INSIST(result == ISC_R_SUCCESS);

		/*
		 * We have a packet: stop timeout timers
		 */
		atomic_store(&dnssock->outerhandle->sock->processing, true);
		if (dnssock->timer_initialized) {
			uv_timer_stop(&dnssock->timer);
		}

		if (atomic_load(&dnssock->sequential)) {
			/*
			 * We're in sequential mode and we processed
			 * one packet, so we're done until the next read
			 * completes.
			 * If we're a client - clear the callback.
			 */
		} else if (dnssock->client && dnssock->rcb.recv == NULL) {
			/*
			 * We're in client mode and we don't have a callback -
			 * pause the read.
			 */
			isc_nm_pauseread(dnssock->outerhandle->sock);
			done = true;
		} else {
			/*
			 * We're pipelining, so we now resume processing
			 * packets until the clients-per-connection limit
			 * is reached (as determined by the number of
			 * active handles on the socket). When the limit
			 * is reached, pause reading.
			 */
			if (atomic_load(&dnssock->ah) >=
			    TCPDNS_CLIENTS_PER_CONN) {
				isc_nm_pauseread(dnssock->outerhandle->sock);
				done = true;
			}
		}

		isc_nmhandle_unref(dnshandle);
	} while (!done);
}

/*
 * isc_nm_listentcpdns listens for connections and accepts
 * them immediately, then calls the cb for each incoming DNS packet
 * (with 2-byte length stripped) - just like for UDP packet.
 */
isc_result_t
isc_nm_listentcpdns(isc_nm_t *mgr, isc_nmiface_t *iface, isc_nm_recv_cb_t cb,
		    void *cbarg, isc_nm_cb_t accept_cb, void *accept_cbarg,
		    size_t extrahandlesize, int backlog, isc_quota_t *quota,
		    isc_nmsocket_t **sockp) {
	/* A 'wrapper' socket object with outer set to true TCP socket */
	isc_nmsocket_t *dnslistensock = isc_mem_get(mgr->mctx,
						    sizeof(*dnslistensock));
	isc_result_t result;

	REQUIRE(VALID_NM(mgr));

	isc__nmsocket_init(dnslistensock, mgr, isc_nm_tcpdnslistener, iface);
	dnslistensock->rcb.recv = cb;
	dnslistensock->rcbarg = cbarg;
	dnslistensock->accept_cb.accept = accept_cb;
	dnslistensock->accept_cbarg = accept_cbarg;
	dnslistensock->extrahandlesize = extrahandlesize;

	/* We set dnslistensock->outer to a true listening socket */
	result = isc_nm_listentcp(mgr, iface, dnslisten_acceptcb, dnslistensock,
				  extrahandlesize, backlog, quota,
				  &dnslistensock->outer);
	if (result == ISC_R_SUCCESS) {
		atomic_store(&dnslistensock->listening, true);
		*sockp = dnslistensock;
		return (ISC_R_SUCCESS);
	} else {
		atomic_store(&dnslistensock->closed, true);
		isc__nmsocket_detach(&dnslistensock);
		return (result);
	}
}

void
isc__nm_tcpdns_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpdnslistener);

	atomic_store(&sock->listening, false);
	atomic_store(&sock->closed, true);
	sock->rcb.recv = NULL;
	sock->rcbarg = NULL;

	if (sock->outer != NULL) {
		isc__nm_tcp_stoplistening(sock->outer);
		isc__nmsocket_detach(&sock->outer);
	}
}

void
isc_nm_tcpdns_sequential(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	if (handle->sock->type != isc_nm_tcpdnssocket ||
	    handle->sock->outerhandle == NULL)
	{
		return;
	}

	/*
	 * We don't want pipelining on this connection. That means
	 * that we need to pause after reading each request, and
	 * resume only after the request has been processed. This
	 * is done in resume_processing(), which is the socket's
	 * closehandle_cb callback, called whenever a handle
	 * is released.
	 */
	isc_nm_pauseread(handle->sock->outerhandle->sock);
	atomic_store(&handle->sock->sequential, true);
}

void
isc_nm_tcpdns_keepalive(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	if (handle->sock->type != isc_nm_tcpdnssocket ||
	    handle->sock->outerhandle == NULL)
	{
		return;
	}

	atomic_store(&handle->sock->keepalive, true);
	atomic_store(&handle->sock->outerhandle->sock->keepalive, true);
}

typedef struct tcpsend {
	isc_mem_t *mctx;
	isc_nmhandle_t *handle;
	isc_region_t region;
	isc_nmhandle_t *orighandle;
	isc_nm_cb_t cb;
	void *cbarg;
} tcpsend_t;

static void
resume_processing(void *arg) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)arg;
	isc_result_t result;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	if (sock->type != isc_nm_tcpdnssocket || sock->outerhandle == NULL) {
		return;
	}

	if (atomic_load(&sock->ah) == 0) {
		/* Nothing is active; sockets can timeout now */
		atomic_store(&sock->outerhandle->sock->processing, false);
		if (sock->timer_initialized) {
			uv_timer_start(&sock->timer, dnstcp_readtimeout,
				       sock->read_timeout, 0);
		}
	}

	/*
	 * For sequential sockets: Process what's in the buffer, or
	 * if there aren't any messages buffered, resume reading.
	 */
	if (atomic_load(&sock->sequential)) {
		isc_nmhandle_t *handle = NULL;

		result = processbuffer(sock, &handle);
		if (result == ISC_R_SUCCESS) {
			atomic_store(&sock->outerhandle->sock->processing,
				     true);
			if (sock->timer_initialized) {
				uv_timer_stop(&sock->timer);
			}
			isc_nmhandle_unref(handle);
		} else if (sock->outerhandle != NULL) {
			isc_nm_resumeread(sock->outerhandle->sock);
		}

		return;
	}

	/*
	 * For pipelined sockets: If we're under the clients-per-connection
	 * limit, resume processing until we reach the limit again.
	 */
	do {
		isc_nmhandle_t *dnshandle = NULL;

		result = processbuffer(sock, &dnshandle);
		if (result != ISC_R_SUCCESS) {
			/*
			 * Nothing in the buffer; resume reading.
			 */
			if (sock->outerhandle != NULL) {
				isc_nm_resumeread(sock->outerhandle->sock);
			}

			break;
		}

		if (sock->timer_initialized) {
			uv_timer_stop(&sock->timer);
		}
		atomic_store(&sock->outerhandle->sock->processing, true);
		isc_nmhandle_unref(dnshandle);
	} while (atomic_load(&sock->ah) < TCPDNS_CLIENTS_PER_CONN);
}

static void
tcpdnssend_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	tcpsend_t *ts = (tcpsend_t *)cbarg;

	ts->cb(ts->orighandle, result, ts->cbarg);
	isc_mem_put(ts->mctx, ts->region.base, ts->region.length);

	isc_nmhandle_unref(ts->orighandle);
	isc_mem_putanddetach(&ts->mctx, ts, sizeof(*ts));

	isc_nmhandle_unref(handle);
}

/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle, isc_region_t *region,
		    isc_nm_cb_t cb, void *cbarg) {
	tcpsend_t *t = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	isc_nmsocket_t *sock = handle->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpdnssocket);

	if (sock->outerhandle == NULL) {
		/* The socket is closed */
		return (ISC_R_NOTCONNECTED);
	}

	t = isc_mem_get(sock->mgr->mctx, sizeof(*t));
	*t = (tcpsend_t){
		.cb = cb,
		.cbarg = cbarg,
		.handle = handle->sock->outerhandle,
	};

	isc_mem_attach(sock->mgr->mctx, &t->mctx);
	t->orighandle = handle;
	isc_nmhandle_ref(t->orighandle);
	isc_nmhandle_ref(t->handle);

	t->region = (isc_region_t){ .base = isc_mem_get(t->mctx,
							region->length + 2),
				    .length = region->length + 2 };

	*(uint16_t *)t->region.base = htons(region->length);
	memmove(t->region.base + 2, region->base, region->length);

	return (isc_nm_send(t->handle, &t->region, tcpdnssend_cb, t));
}

static void
tcpdns_close_direct(isc_nmsocket_t *sock) {
	REQUIRE(sock->tid == isc_nm_tid());

	/* We don't need atomics here, it's all in single network thread */
	if (sock->timer_initialized) {
		/*
		 * We need to fire the timer callback to clean it up,
		 * it will then call us again (via detach) so that we
		 * can finally close the socket.
		 */
		sock->timer_initialized = false;
		uv_timer_stop(&sock->timer);
		uv_close((uv_handle_t *)&sock->timer, timer_close_cb);
	} else if (sock->self != NULL) {
		isc__nmsocket_detach(&sock->self);
	} else {
		/*
		 * At this point we're certain that there are no external
		 * references, we can close everything.
		 */
		if (sock->outerhandle != NULL) {
			sock->outerhandle->sock->rcb.recv = NULL;
			isc_nmhandle_unref(sock->outerhandle);
			sock->outerhandle = NULL;
		}
		if (sock->listener != NULL) {
			isc__nmsocket_detach(&sock->listener);
		}
		atomic_store(&sock->closed, true);
		isc__nmsocket_prep_destroy(sock);
	}
}

void
isc__nm_tcpdns_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tcpdnssocket);

	if (sock->tid == isc_nm_tid()) {
		tcpdns_close_direct(sock);
	} else {
		isc__netievent_tcpdnsclose_t *ievent =
			isc__nm_get_ievent(sock->mgr, netievent_tcpdnsclose);

		ievent->sock = sock;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_async_tcpdnsclose(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpdnsclose_t *ievent =
		(isc__netievent_tcpdnsclose_t *)ev0;

	REQUIRE(worker->id == ievent->sock->tid);

	tcpdns_close_direct(ievent->sock);
}

typedef struct tcpconnect {
	isc_mem_t *mctx;
	isc_nm_cb_t cb;
	void *cbarg;
	size_t extrahandlesize;
} tcpconnect_t;

static void
tcpdnsconnect_cb(isc_nmhandle_t *handle, isc_result_t result, void *ncbarg_) {
	tcpconnect_t *ncbarg = (tcpconnect_t *)ncbarg_;
	isc_nm_cb_t cb = ncbarg->cb;
	void *cbarg = ncbarg->cbarg;
	size_t extrahandlesize = ncbarg->extrahandlesize;
	isc_mem_putanddetach(&ncbarg->mctx, ncbarg, sizeof(*ncbarg));

	if (result != ISC_R_SUCCESS) {
		cb(NULL, result, cbarg);
		return;
	}
	INSIST(VALID_NMHANDLE(handle));

	isc_nmsocket_t *dnssock = isc_mem_get(handle->sock->mgr->mctx,
					      sizeof(*dnssock));
	isc__nmsocket_init(dnssock, handle->sock->mgr, isc_nm_tcpdnssocket,
			   handle->sock->iface);

	dnssock->extrahandlesize = extrahandlesize;
	dnssock->outerhandle = handle;
	isc_nmhandle_ref(dnssock->outerhandle);

	dnssock->peer = handle->sock->peer;
	dnssock->read_timeout = handle->sock->mgr->init;
	dnssock->tid = isc_nm_tid();

	dnssock->client = true;
	dnssock->statichandle = isc__nmhandle_get(dnssock, NULL, NULL);
	
	uv_timer_init(&dnssock->mgr->workers[isc_nm_tid()].loop,
		      &dnssock->timer);
	dnssock->timer.data = dnssock;
	dnssock->timer_initialized = true;
	uv_timer_start(&dnssock->timer, dnstcp_readtimeout,
		       dnssock->read_timeout, 0);
	/*
	 * We start reading not asked to - we'll read and buffer
	 * at most one packet.
	 */
	result = isc_nm_read(handle, dnslisten_readcb, dnssock);
	if (result != ISC_R_SUCCESS) {
		isc_nmhandle_unref(handle);
	}

	cb(dnssock->statichandle, ISC_R_SUCCESS, cbarg);
	isc_nmhandle_unref(dnssock->statichandle);
	isc__nmsocket_detach(&dnssock);
}

isc_result_t
isc_nm_tcpdnsconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		     isc_nm_cb_t cb, void *cbarg, size_t extrahandlesize) {
	tcpconnect_t *ncbarg = isc_mem_get(mgr->mctx, sizeof(tcpconnect_t));
	*ncbarg = (tcpconnect_t){ .cb = cb,
				  .cbarg = cbarg,
				  .extrahandlesize = extrahandlesize };
	isc_mem_attach(mgr->mctx, &ncbarg->mctx);
	return (isc_nm_tcpconnect(mgr, local, peer, tcpdnsconnect_cb, ncbarg,
				  0));
}

isc_result_t
isc__nm_tcpdns_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	/*
	 * This HAS to be done asynchronously - read is often called from the
	 * read callback, we'd clash in processbuffer() AND grow the stack
	 * indefinitely.
	 */
	isc_nmsocket_t *sock = handle->sock;
	INSIST(handle == sock->statichandle);
	INSIST(sock->rcb.recv == NULL);
	isc__netievent_tcpdnsread_t *ievent =
		isc__nm_get_ievent(sock->mgr, netievent_tcpdnsread);
	ievent->sock = sock;
	sock->rcb.recv = cb;
	sock->rcbarg = cbarg;
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
	return (ISC_R_SUCCESS);
}

void
isc__nm_async_tcpdnsread(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tcpdnsread_t *ievent =
		(isc__netievent_tcpdnsclose_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(worker->id == sock->tid);
	isc_nmhandle_t *handle = sock->statichandle;

	isc_result_t result;

	if (sock->type != isc_nm_tcpdnssocket || sock->outerhandle == NULL) {
		sock->rcb.recv(handle, ISC_R_NOTCONNECTED, NULL, sock->rcbarg);
		return;
	}

	/* Maybe we have a packet already? */
	isc_nmhandle_t *newhandle = NULL;
	result = processbuffer(sock, &newhandle);
	if (result == ISC_R_SUCCESS) {
		atomic_store(&sock->outerhandle->sock->processing,
			     true);
		if (sock->timer_initialized) {
			uv_timer_stop(&sock->timer);
		}
		isc_nmhandle_unref(handle);
	} else if (sock->outerhandle != NULL) {
		/* Restart reading, wait for the callback */
		atomic_store(&sock->outerhandle->sock->processing,
			     false);
		if (sock->timer_initialized) {
			uv_timer_start(&sock->timer, dnstcp_readtimeout,
				       sock->read_timeout, 0);
		}
		isc_nm_resumeread(sock->outerhandle->sock);
	} else {
		isc_nm_recv_cb_t cb = sock->rcb.recv;
		void *cbarg = sock->rcbarg;
		sock->rcb.recv = NULL;
		sock->rcbarg = NULL;
		cb(handle, ISC_R_NOTCONNECTED, NULL, cbarg);
	}
}
