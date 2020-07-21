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

#include <libgen.h>
#include <unistd.h>
#include <uv.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/quota.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/stdtime.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"
#include "uv-compat.h"
#define TLS_CHECK_RV INT_MAX
static void
tls_do_bio(isc_nmsocket_t *sock, int rv);

static void
tls_close_direct(isc_nmsocket_t *sock);

static void
tls_senddone(isc_nmhandle_t *t, isc_result_t res, void *arg) {
	(void)res;
	(void)t;
	isc_nmsocket_t *sock = (isc_nmsocket_t *)arg;
	/*	if (sock->tls.state != IO) {
			int rv = SSL_is_init_finished(sock->tls.ssl);
			if (rv != 1) {
			}
		} */
	tls_do_bio(sock, TLS_CHECK_RV);
}

static void
tls_do_bio(isc_nmsocket_t *sock, int rv) {
	INSIST(sock->tid == isc_nm_tid());
	if (rv == TLS_CHECK_RV) {
		char buf[1];
		rv = SSL_peek(sock->tls.ssl, buf, 1);
		if (rv == 1) {
			if (sock->rcb.recv != NULL &&
			    !atomic_load(&sock->readpaused)) {
				isc_region_t region = { malloc(4096), 4096 };
				memset(region.base, 0, region.length);
				rv = SSL_read(sock->tls.ssl, region.base,
					      region.length);
				isc_region_t dregion =
					(isc_region_t){ region.base, rv };
				sock->rcb.recv(sock->tcphandle, ISC_R_SUCCESS,
					       &dregion, sock->rcbarg);
				free(region.base);
			}
		}
	}
	int pending = BIO_pending(sock->tls.app_bio);
	if (pending > 0) {
		char *p = malloc(pending);
		int s;
		rv = BIO_read(sock->tls.app_bio, p, pending);
		s = isc_nm_send(sock->outerhandle,
				&(isc_region_t){ (unsigned char *)p, rv },
				tls_senddone, sock);
		if (s != rv) {
			goto error;
		}
	}

	int err = SSL_get_error(sock->tls.ssl, rv);
	if (err == 0) {
		return;
	} else if (err == SSL_ERROR_WANT_WRITE) {
		isc_nm_pauseread(sock->outerhandle);
		pending = BIO_pending(sock->tls.app_bio);
		if (pending > 0) {
			int s;
			char *p = malloc(pending);
			rv = BIO_read(sock->tls.app_bio, p, pending);
			s = isc_nm_send(
				sock->outerhandle,
				&(isc_region_t){ (unsigned char *)p, rv },
				tls_senddone, sock);
			if (s != rv) {
				goto error;
			}
		}
	} else if (err == SSL_ERROR_WANT_READ) {
		isc_nm_resumeread(sock->outerhandle);
	} else {
		goto error;
	}
	return;
error:
	/* XXXWPK TODO log it ! */
	if (sock->rcb.recv != NULL) {
		sock->rcb.recv(sock->tcphandle, ISC_R_SUCCESS, NULL,
			       sock->rcbarg);
	} else {
		tls_close_direct(sock);
	}
}

static void
tls_readcb(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *region,
	   void *arg) {
	isc_nmsocket_t *tlssock = (isc_nmsocket_t *)arg;
	int rv;

	REQUIRE(VALID_NMSOCK(tlssock));
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(tlssock->tid == isc_nm_tid());

	if (result != ISC_R_SUCCESS) {
		/* Connection closed */
		/* TODO accept_cb should be called if we're not initialized yet!
		 */
		if (tlssock->rcb.recv != NULL) {
			tlssock->rcb.recv(tlssock->tcphandle, result, region,
					  tlssock->rcbarg);
		}
		isc__nm_tls_close(tlssock);
		return;
	}

	rv = BIO_write(tlssock->tls.app_bio, region->base, region->length);
	INSIST(rv > 0 && (unsigned int)rv == region->length);
	tls_do_bio(tlssock, TLS_CHECK_RV);
	if (tlssock->tls.state != IO) {
		if (SSL_is_init_finished(tlssock->tls.ssl) == 1) {
			if (tlssock->server) {
				tlssock->listener->accept_cb.accept(
					tlssock->tcphandle, ISC_R_SUCCESS,
					tlssock->listener->accept_cbarg);
			} else {
				tlssock->accept_cb.connect(
					tlssock->tcphandle, ISC_R_SUCCESS,
					tlssock->accept_cbarg);
			}
			tlssock->tls.state = IO;
			/* We need to do it again - to flush incoming buffer */
			tls_do_bio(tlssock, TLS_CHECK_RV);
		}
	}
}

static isc_result_t
initialize_tls(isc_nmsocket_t *sock, bool srv) {
	INSIST(sock->tid == isc_nm_tid());
	sock->tls.ssl = SSL_new(sock->tls.ctx);
	if (sock->tls.ssl == NULL) {
		return (ISC_R_TLSERROR);
	}

	if (BIO_new_bio_pair(&(sock->tls.ssl_bio), 0, &(sock->tls.app_bio),
			     0) != 1) {
		SSL_free(sock->tls.ssl);
		return (ISC_R_TLSERROR);
	}
	SSL_set_bio(sock->tls.ssl, sock->tls.ssl_bio, sock->tls.ssl_bio);
	if (srv) {
		SSL_set_accept_state(sock->tls.ssl);
	} else {
		SSL_set_connect_state(sock->tls.ssl);
	}
	isc_nm_read(sock->outerhandle, tls_readcb, sock);
	tls_do_bio(sock, TLS_CHECK_RV);
	return (ISC_R_SUCCESS);
}

static isc_result_t
tlslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *tlslistensock = (isc_nmsocket_t *)cbarg;
	isc_nmsocket_t *tlssock = NULL;
	REQUIRE(VALID_NMSOCK(tlslistensock));
	REQUIRE(tlslistensock->type == isc_nm_tlslistener);

	/* If accept() was unsuccessful we can't do anything */
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	/* We need to create a 'wrapper' tlssocket for this connection */
	tlssock = isc_mem_get(handle->sock->mgr->mctx, sizeof(*tlssock));
	isc__nmsocket_init(tlssock, handle->sock->mgr, isc_nm_tlssocket,
			   handle->sock->iface);

	tlssock->extrahandlesize = tlslistensock->extrahandlesize;
	isc__nmsocket_attach(tlslistensock, &tlssock->listener);
	isc_nmhandle_ref(handle);
	tlssock->outerhandle = handle;
	tlssock->peer = handle->sock->peer;
	tlssock->read_timeout = handle->sock->mgr->init;
	tlssock->tid = isc_nm_tid();
	tlssock->tls.server = true;
	isc__nmhandle_get(tlssock, NULL, NULL);

	uv_timer_init(&tlssock->mgr->workers[isc_nm_tid()].loop,
		      &tlssock->timer);
	tlssock->timer.data = tlssock;
	tlssock->timer_initialized = true;
	tlssock->tls.ctx = tlslistensock->tls.ctx;
	result = initialize_tls(tlssock, true);
	if (result != ISC_R_SUCCESS) {
		isc__nmsocket_detach(&tlssock);
		abort();
		/* TODO log about it! */
		return (result);
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_nm_listentls(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_accept_cb_t accept_cb, void *accept_cbarg,
		 size_t extrahandlesize, int backlog, isc_quota_t *quota,
		 SSL_CTX *sslctx, isc_nmsocket_t **sockp) {
	isc_result_t result;
	isc_nmsocket_t *tlssock = isc_mem_get(mgr->mctx, sizeof(*tlssock));

	isc__nmsocket_init(tlssock, mgr, isc_nm_tlslistener, iface);
	tlssock->accept_cb.accept = accept_cb;
	tlssock->accept_cbarg = accept_cbarg;
	tlssock->extrahandlesize = extrahandlesize;
	tlssock->tls.ctx = sslctx;

	/* We set dnslistensock->outer to a true listening socket */
	result = isc_nm_listentcp(mgr, iface, tlslisten_acceptcb, tlssock,
				  extrahandlesize, backlog, quota,
				  &tlssock->outer);
	if (result == ISC_R_SUCCESS) {
		atomic_store(&tlssock->listening, true);
		*sockp = tlssock;
		return (ISC_R_SUCCESS);
	} else {
		atomic_store(&tlssock->closed, true);
		isc__nmsocket_detach(&tlssock);
		return (result);
	}
}
static isc_result_t
tls_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req);

void
isc__nm_async_tlssend(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc_result_t result;
	isc__netievent_tcpsend_t *ievent = (isc__netievent_tcpsend_t *)ev0;

	REQUIRE(worker->id == ievent->sock->tid);

	if (!atomic_load(&ievent->sock->active)) {
		return;
	}

	result = tls_send_direct(ievent->sock, ievent->req);
	if (result != ISC_R_SUCCESS) {
		ievent->req->cb.send(ievent->req->handle, result,
				     ievent->req->cbarg);
		isc__nm_uvreq_put(&ievent->req, ievent->req->handle->sock);
	}
}

static isc_result_t
tls_send_direct(isc_nmsocket_t *sock, isc__nm_uvreq_t *req) {
	REQUIRE(sock->tid == isc_nm_tid());
	REQUIRE(sock->type == isc_nm_tlssocket);

	int rv = SSL_write(sock->tls.ssl, req->uvbuf.base, req->uvbuf.len);
	if (rv < 0) {
		isc__nm_uvreq_put(&req, sock);
		return (isc__nm_uverr2result(rv));
	}
	INSIST((unsigned)rv == req->uvbuf.len);
	tls_do_bio(sock, TLS_CHECK_RV);
	req->cb.send(sock->tcphandle, ISC_R_SUCCESS, req->cbarg);
	isc__nm_uvreq_put(&req, sock);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc__nm_tls_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
		 void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	isc__netievent_tcpsend_t *ievent = NULL;
	isc__nm_uvreq_t *uvreq = NULL;

	REQUIRE(sock->type == isc_nm_tlssocket);

	uvreq = isc__nm_uvreq_get(sock->mgr, sock);
	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;
	uvreq->handle = handle;
	isc_nmhandle_ref(uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	if (sock->tid == isc_nm_tid()) {
		/*
		 * If we're in the same thread as the socket we can send the
		 * data directly
		 */
		return (tls_send_direct(sock, uvreq));
	} else {
		/*
		 * We need to create an event and pass it using async channel
		 */
		ievent = isc__nm_get_ievent(sock->mgr, netievent_tlssend);
		ievent->sock = sock;
		ievent->req = uvreq;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
		return (ISC_R_SUCCESS);
	}

	return (ISC_R_UNEXPECTED);
}

void
isc__nm_async_tls_startread(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_startread_t *ievent = (isc__netievent_startread_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(worker->id == isc_nm_tid());
	tls_do_bio(sock, TLS_CHECK_RV);
}

isc_result_t
isc__nm_tls_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock = NULL;
	isc__netievent_startread_t *ievent = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;
	sock->rcb.recv = cb;
	sock->rcbarg = cbarg;

	ievent = isc__nm_get_ievent(sock->mgr, netievent_tcpstartread);
	ievent->sock = sock;

	if (sock->tid == isc_nm_tid()) {
		isc__nm_async_tls_startread(&sock->mgr->workers[sock->tid],
					    (isc__netievent_t *)ievent);
		isc__nm_put_ievent(sock->mgr, ievent);
	} else {
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc__nm_tls_pauseread(isc_nmsocket_t *sock) {
	atomic_store(&sock->readpaused, true);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc__nm_tls_resumeread(isc_nmsocket_t *sock) {
	atomic_store(&sock->readpaused, false);
	return (ISC_R_SUCCESS);
}

static void
timer_close_cb(uv_handle_t *handle) {
	isc_nmsocket_t *sock = (isc_nmsocket_t *)uv_handle_get_data(handle);
	INSIST(VALID_NMSOCK(sock));
	isc__nmsocket_detach(&sock);
}

static void
tls_close_direct(isc_nmsocket_t *sock) {
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
	} else {
		/*
		 * At this point we're certain that there are no external
		 * references, we can close everything.
		 */
		if (sock->outerhandle != NULL) {
			sock->outer->rcb.recv = NULL;
			isc__nmsocket_detach(&sock->outer);
		}
		if (sock->listener != NULL) {
			isc__nmsocket_detach(&sock->listener);
		}
		atomic_store(&sock->closed, true);
	}
}

void
isc__nm_tls_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tlssocket);

	if (sock->tid == isc_nm_tid()) {
		tls_close_direct(sock);
	} else {
		isc__netievent_tlsclose_t *ievent =
			isc__nm_get_ievent(sock->mgr, netievent_tlsclose);

		ievent->sock = sock;
		isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
				       (isc__netievent_t *)ievent);
	}
}

void
isc__nm_async_tlsclose(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsclose_t *ievent = (isc__netievent_tlsclose_t *)ev0;

	REQUIRE(worker->id == ievent->sock->tid);

	tls_close_direct(ievent->sock);
}

void
isc__nm_tls_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_tlslistener);

	atomic_store(&sock->listening, false);
	atomic_store(&sock->closed, true);
	sock->rcb.recv = NULL;
	sock->rcbarg = NULL;

	if (sock->outer != NULL) {
		isc_nm_stoplistening(sock->outer);
		isc__nmsocket_detach(&sock->outer);
	}
}

isc_result_t
isc_nm_tlsconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		  isc_nm_accept_cb_t cb, void *cbarg, SSL_CTX *ctx,
		  size_t extrahandlesize) {
	isc_nmsocket_t *nsock = NULL, *tmp = NULL;
	isc__netievent_tlsconnect_t *ievent = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(VALID_NM(mgr));

	nsock = isc_mem_get(mgr->mctx, sizeof(*nsock));
	isc__nmsocket_init(nsock, mgr, isc_nm_tlssocket, local);
	nsock->extrahandlesize = extrahandlesize;
	nsock->result = ISC_R_SUCCESS;
	nsock->accept_cb.accept = cb;
	nsock->accept_cbarg = cbarg;
	nsock->tls.ctx = ctx;

	ievent = isc__nm_get_ievent(mgr, netievent_tlsconnect);
	ievent->sock = nsock;
	ievent->local = local->addr;
	ievent->peer = peer->addr;
	ievent->ctx = ctx;

	/*
	 * Async callbacks can dereference the socket in the meantime,
	 * we need to hold an additional reference to it.
	 */
	isc__nmsocket_attach(nsock, &tmp);

	if (isc__nm_in_netthread()) {
		nsock->tid = isc_nm_tid();
		isc__nm_async_tlsconnect(&mgr->workers[nsock->tid],
					 (isc__netievent_t *)ievent);
		isc__nm_put_ievent(mgr, ievent);
	} else {
		nsock->tid = isc_random_uniform(mgr->nworkers);
		isc__nm_enqueue_ievent(&mgr->workers[nsock->tid],
				       (isc__netievent_t *)ievent);

		LOCK(&nsock->lock);
		while (!atomic_load(&nsock->connected) &&
		       !atomic_load(&nsock->connect_error)) {
			WAIT(&nsock->cond, &nsock->lock);
		}
		UNLOCK(&nsock->lock);
	}

	if (nsock->result != ISC_R_SUCCESS) {
		result = nsock->result;
		isc__nmsocket_detach(&nsock);
	}

	isc__nmsocket_detach(&tmp);

	return (result);
}

static void
tls_connect_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *tlssock = (isc_nmsocket_t *)cbarg;
	INSIST(VALID_NMSOCK(tlssock));
	if (result != ISC_R_SUCCESS) {
		tlssock->accept_cb.connect(NULL, result, tlssock->accept_cbarg);
		return;
	}

	tlssock->outerhandle = handle;
	isc_nmhandle_ref(handle);
	result = initialize_tls(tlssock, true);
	if (result != ISC_R_SUCCESS) {
		tlssock->accept_cb.connect(NULL, result, tlssock->accept_cbarg);
		/* TODO CLOSE! */
		return;
	}
}

void
isc__nm_async_tlsconnect(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_tlsconnect_t *ievent =
		(isc__netievent_tlsconnect_t *)ev0;
	isc_nmsocket_t *tlssock = ievent->sock;
	isc_result_t result;

	UNUSED(worker);

	tlssock->tid = isc_nm_tid();
	uv_timer_init(&tlssock->mgr->workers[isc_nm_tid()].loop,
		      &tlssock->timer);
	tlssock->timer.data = tlssock;
	tlssock->timer_initialized = true;

	result = isc_nm_tcpconnect(worker->mgr, (isc_nmiface_t *)&ievent->local,
				   (isc_nmiface_t *)&ievent->peer,
				   tls_connect_cb, tlssock, 0);
	if (result != ISC_R_SUCCESS) {
		tlssock->accept_cb.connect(NULL, result, tlssock->accept_cbarg);
		/* TODO CLOSE! */
		return;
	}
}
