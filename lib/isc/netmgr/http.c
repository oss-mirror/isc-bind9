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

#include <nghttp2/nghttp2.h>
#include <signal.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/base64.h>
#include <isc/netmgr.h>

#include "netmgr-int.h"
#include "url-parser/url_parser.h"

#define AUTHEXTRA 7

typedef struct {
	char *uri;
	struct http_parser_url u;

	char *authority;
	size_t authoritylen;
	char *path;

	size_t pathlen;
	int32_t stream_id;
	isc_region_t *postdata;
	size_t postdata_pos;
} http2_stream;

typedef struct {
	isc_mem_t *mctx;
	nghttp2_session *ngsession;
	http2_stream *stream;
	isc_nmhandle_t *handle;

	uint8_t buf[65535];
	size_t bufsize;
	uint8_t rbuf[65535];
	size_t rbufsize;

	isc_nm_recv_cb_t cb;
	void *cbarg;

	SSL_CTX *ctx;
	bool reading;
} http2_session;

static bool
http2_do_bio(http2_session *session);

static void
writecb(isc_nmhandle_t *handle, isc_result_t result, void *ptr);

static isc_result_t
get_http2_stream(isc_mem_t *mctx, http2_stream **streamp, const char *uri,
		 uint16_t *port) {
	INSIST(streamp != NULL && *streamp == NULL);
	INSIST(uri != NULL);
	INSIST(port != NULL);

	int rv;
	http2_stream *stream = isc_mem_get(mctx, sizeof(http2_stream));
	stream->uri = isc_mem_strdup(mctx, uri);
	rv = http_parser_parse_url(stream->uri, strlen(stream->uri), 0,
				   &stream->u);
	if (rv != 0) {
		isc_mem_put(mctx, stream, sizeof(http2_stream));
		isc_mem_free(mctx, stream->uri);
		return (ISC_R_FAILURE);
	}
	stream->stream_id = -1;

	stream->authoritylen = stream->u.field_data[UF_HOST].len;
	stream->authority = isc_mem_get(mctx, stream->authoritylen + AUTHEXTRA);
	memcpy(stream->authority, &uri[stream->u.field_data[UF_HOST].off],
	       stream->u.field_data[UF_HOST].len);
	if (stream->u.field_set & (1 << UF_PORT)) {
		stream->authoritylen += (size_t)snprintf(
			stream->authority + stream->u.field_data[UF_HOST].len,
			AUTHEXTRA, ":%u", stream->u.port);
	}

	/* If we don't have path in URI, we use "/" as path. */
	stream->pathlen = 1;
	if (stream->u.field_set & (1 << UF_PATH)) {
		stream->pathlen = stream->u.field_data[UF_PATH].len;
	}
	if (stream->u.field_set & (1 << UF_QUERY)) {
		/* +1 for '?' character */
		stream->pathlen +=
			(size_t)(stream->u.field_data[UF_QUERY].len + 1);
	}

	stream->path = isc_mem_get(mctx, stream->pathlen);
	if (stream->u.field_set & (1 << UF_PATH)) {
		memcpy(stream->path, &uri[stream->u.field_data[UF_PATH].off],
		       stream->u.field_data[UF_PATH].len);
	} else {
		stream->path[0] = '/';
	}
	if (stream->u.field_set & (1 << UF_QUERY)) {
		stream->path[stream->pathlen -
			     stream->u.field_data[UF_QUERY].len - 1] = '?';
		memcpy(stream->path + stream->pathlen -
			       stream->u.field_data[UF_QUERY].len,
		       &uri[stream->u.field_data[UF_QUERY].off],
		       stream->u.field_data[UF_QUERY].len);
	}

	if (!(stream->u.field_set & (1 << UF_PORT))) {
		*port = 443;
	} else {
		*port = stream->u.port;
	}
	*streamp = stream;
	return (ISC_R_SUCCESS);
}

static void
put_http2_stream(isc_mem_t *mctx, http2_stream *stream) {
	isc_mem_put(mctx, stream->path, stream->pathlen);
	isc_mem_put(mctx, stream->authority, stream->authoritylen + AUTHEXTRA);
	isc_mem_put(mctx, stream, sizeof(http2_stream));
}

static void
delete_http2_session(http2_session *session) {
	if (session->handle != NULL) {
		isc_nmhandle_unref(session->handle);
		session->handle = NULL;
	}
	if (session->ngsession != NULL) {
		nghttp2_session_del(session->ngsession);
		session->ngsession = NULL;
	}
	if (session->stream != NULL) {
		put_http2_stream(session->mctx, session->stream);
		session->stream = NULL;
	}

	isc_mem_putanddetach(&session->mctx, session, sizeof(http2_session));
}

#if 0
/* XXXWPK do we need these callback? We might want to verify headers */
on_header_callback(nghttp2_session *ngsession, const nghttp2_frame *frame,
		   const uint8_t *name, size_t namelen, const uint8_t *value,
		   size_t valuelen, uint8_t flags, void *user_data) {
	http2_session *session = (http2_session *)user_data;
	UNUSED(ngsession);
	UNUSED(flags);
	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
		    session->stream->stream_id == frame->hd.stream_id)
		{
			break;
		}
	}
	return (0);
}

static int
on_begin_headers_callback(nghttp2_session *ngsession, const nghttp2_frame *frame,
			  void *user_data) {
	http2_session *session = (http2_session *)user_data;
	UNUSED(ngsession);
	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
		    session->stream->stream_id == frame->hd.stream_id)
		{
			/* XXX */
		}
		break;
	}
	return (0);
}

on_frame_recv_callback(nghttp2_session *ngsession, const nghttp2_frame *frame,
		       void *user_data) {
	http2_session *session = (http2_session *)user_data;
	UNUSED(ngsession);
	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
		    session->stream->stream_id == frame->hd.stream_id)
		{
			/* XXX */
		}
		break;
	}
	return (0);
}
#endif

static int
on_data_chunk_recv_callback(nghttp2_session *ngsession, uint8_t flags,
			    int32_t stream_id, const uint8_t *data, size_t len,
			    void *user_data) {
	http2_session *session = (http2_session *)user_data;
	UNUSED(ngsession);
	UNUSED(flags);
	if (session->stream->stream_id == stream_id) {
		/* TODO buffer overrun! */
		memmove(session->rbuf + session->rbufsize, data, len);
		session->rbufsize += len;
	}
	return (0);
}

static int
on_stream_close_callback(nghttp2_session *ngsession, int32_t stream_id,
			 uint32_t error_code, void *user_data) {
	UNUSED(error_code);
	
	http2_session *session = (http2_session *)user_data;
	int rv;
	if (session->stream->stream_id == stream_id) {
		rv = nghttp2_session_terminate_session(ngsession,
						       NGHTTP2_NO_ERROR);
		if (rv != 0) {
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		}
	}
	session->cb(NULL, ISC_R_SUCCESS,
		    &(isc_region_t){ session->rbuf, session->rbufsize },
		    session->cbarg);
	/* XXXWPK TODO we need to close the session */

	return (0);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/* NPN TLS extension client callback. We check that server advertised
   the HTTP/2 protocol the nghttp2 library supports. If not, exit
   the program. */
static int
select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen,
		     const unsigned char *in, unsigned int inlen, void *arg) {
	UNUSED(ssl);
	UNUSED(arg);

	if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
		/* TODO */
	}
	return (SSL_TLSEXT_ERR_OK);
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

/* Create SSL_CTX. */
static SSL_CTX *
create_ssl_ctx(void) {
	SSL_CTX *ssl_ctx;
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ssl_ctx) {
		/* TODO */
		abort();
	}
	SSL_CTX_set_options(
		ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
				 SSL_OP_NO_COMPRESSION |
				 SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

	return (ssl_ctx);
}

static void
initialize_nghttp2_session(http2_session *session) {
	nghttp2_session_callbacks *callbacks;

	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, on_stream_close_callback);

#if 0
/* Do we need it ? */
	nghttp2_session_callbacks_set_on_header_callback(callbacks,
							 on_header_callback);

	nghttp2_session_callbacks_set_on_begin_headers_callback(
		callbacks, on_begin_headers_callback);

	nghttp2_session_callbacks_set_on_frame_recv_callback(
		callbacks, on_frame_recv_callback);

#endif

	nghttp2_session_client_new(&session->ngsession, callbacks, session);

	nghttp2_session_callbacks_del(callbacks);
}

static void
send_client_connection_header(http2_session *session) {
	nghttp2_settings_entry iv[1] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
	};
	int rv;

	rv = nghttp2_submit_settings(session->ngsession, NGHTTP2_FLAG_NONE, iv,
				     1);
	if (rv != 0) {
		/* TODO */
	}
	http2_do_bio(session);
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
	{                                                                      \
		(uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN, \
			NGHTTP2_NV_FLAG_NONE                                   \
	}

#define MAKE_NV2(NAME, VALUE)                                        \
	{                                                            \
		(uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, \
			sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE      \
	}

static ssize_t
post_read_callback(nghttp2_session *ngsession, int32_t stream_id, uint8_t *buf,
		   size_t length, uint32_t *data_flags,
		   nghttp2_data_source *source, void *user_data) {
	http2_session *session = (http2_session *)user_data;
	UNUSED(ngsession);
	UNUSED(source);

	if (session->stream->stream_id == stream_id) {
		size_t len = session->stream->postdata->length -
			     session->stream->postdata_pos;
		if (len > length) {
			len = length;
		}
		memcpy(buf,
		       session->stream->postdata->base +
			       session->stream->postdata_pos,
		       len);
		session->stream->postdata_pos += len;
		if (session->stream->postdata_pos ==
		    session->stream->postdata->length) {
			*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		}
		return (len);
	}
	return (0);
}

/* Send HTTP request to the remote peer */
static isc_result_t
submit_request(http2_session *session) {
	int32_t stream_id;
	http2_stream *stream = session->stream;
	char *uri = stream->uri;
	struct http_parser_url *u = &stream->u;
	char p[64];
	snprintf(p, 64, "%u", stream->postdata->length);

	nghttp2_nv hdrs[] = {
		MAKE_NV2(":method", "POST"),
		MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
			u->field_data[UF_SCHEMA].len),
		MAKE_NV(":authority", stream->authority, stream->authoritylen),
		MAKE_NV(":path", stream->path, stream->pathlen),
		MAKE_NV2("content-type", "application/dns-message"),
		MAKE_NV2("accept", "application/dns-message"),
		MAKE_NV("content-length", p, strlen(p))
	};

	nghttp2_data_provider dp = { .read_callback = post_read_callback };
	stream_id = nghttp2_submit_request(session->ngsession, NULL, hdrs, 7,
					   &dp, stream);
	if (stream_id < 0) {
		return (ISC_R_FAILURE);
	}
	stream->stream_id = stream_id;
	http2_do_bio(session);
	return (ISC_R_SUCCESS);
}

/*
 * read callback from TLS socket.
 */
static void
readcb(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *region,
       void *data) {
	UNUSED(handle);
	UNUSED(result);
	http2_session *session = (http2_session *)data;

	ssize_t readlen = nghttp2_session_mem_recv(
		session->ngsession, region->base, region->length);

	if (readlen < 0) {
		delete_http2_session(session);
		/* TODO callback! */
		return;
	}
	if (readlen < region->length) {
		INSIST(session->bufsize == 0);
		INSIST(region->length - readlen < 65535);
		memmove(session->buf, region->base, region->length - readlen);
		session->bufsize = region->length - readlen;
		isc_nm_pauseread(session->handle);
	}

	/* We might have something to receive or send, do IO */
	http2_do_bio(session);
}

static bool
http2_do_bio(http2_session *session) {
	if (nghttp2_session_want_read(session->ngsession) == 0 &&
	    nghttp2_session_want_write(session->ngsession) == 0)
	{
		delete_http2_session(session);
		return (false);
	}

	if (nghttp2_session_want_read(session->ngsession) != 0) {
		if (!session->reading) {
			/* We have not yet started reading from this handle */
			isc_nm_read(session->handle, readcb, session);
			session->reading = true;
		} else if (session->bufsize > 0) {
			/* Leftover data in the buffer, use it */
			size_t readlen = nghttp2_session_mem_recv(
				session->ngsession, session->buf,
				session->bufsize);
			if (readlen == session->bufsize) {
				session->bufsize = 0;
			} else {
				memmove(session->buf, session->buf + readlen,
					session->bufsize - readlen);
				session->bufsize -= readlen;
			}
			http2_do_bio(session);
			return (false);
		} else {
			/* Resume reading, it's idempotent, wait for more */
			isc_nm_resumeread(session->handle);
		}
	} else {
		/* We don't want more data, stop reading for now */
		isc_nm_pauseread(session->handle);
	}

	if (nghttp2_session_want_write(session->ngsession) != 0) {
		const uint8_t *data;

		/*
		 * XXXWPK TODO
		 * This function may produce very small byte string.  If that
		 * is the case, and application disables Nagle algorithm
		 * (``TCP_NODELAY``), then writing this small chunk leads to
		 * very small packet, and it is very inefficient.  An
		 * application should be responsible to buffer up small chunks
		 * of data as necessary to avoid this situation.
		 */
		size_t sz = nghttp2_session_mem_send(session->ngsession, &data);
		isc_region_t region;
		region.base = malloc(sz);
		region.length = sz;
		memcpy(region.base, data, sz);
		isc_result_t result = isc_nm_send(session->handle, &region,
						  writecb, session);
		if (result != ISC_R_SUCCESS) {
			abort();
		}
		return (true);
	}
	return (false);
}

static void
writecb(isc_nmhandle_t *handle, isc_result_t result, void *ptr) {
	UNUSED(handle);
	UNUSED(result);
	http2_session *session = (http2_session *)ptr;
	http2_do_bio(session);
}

static void
connect_cb(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	http2_session *session = (http2_session *)arg;
	if (result != ISC_R_SUCCESS) {
		delete_http2_session(session);
		return;
	}
	session->handle = handle;
	isc_nmhandle_ref(handle);

#if 0
/* TODO H2 */
#ifndef OPENSSL_NO_NEXTPROTONEG
			SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
			if (alpn == NULL) {
				SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
			}
#endif

			if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0)
			{
				fprintf(stderr, "h2 is not negotiated\n");
				delete_http2_session(session);
				return;
			}
#endif
	initialize_nghttp2_session(session);
	send_client_connection_header(session);
	submit_request(session);
	http2_do_bio(session);
}

isc_result_t
isc_nm_doh_request(isc_nm_t *mgr, const char *uri, isc_region_t *message,
		   isc_nm_recv_cb_t cb, void *cbarg, SSL_CTX *ctx) {
	uint16_t port;
	char *host;
	http2_session *session;
	struct addrinfo hints;
	struct addrinfo *res;
	isc_sockaddr_t local, peer;
	isc_result_t result;

	if (ctx == NULL) {
		ctx = create_ssl_ctx();
	}

	session = isc_mem_get(mgr->mctx, sizeof(http2_session));
	*session = (http2_session){ .cb = cb, .cbarg = cbarg, .ctx = ctx };
	isc_mem_attach(mgr->mctx, &session->mctx);

	result = get_http2_stream(mgr->mctx, &session->stream, uri, &port);
	if (result != ISC_R_SUCCESS) {
		delete_http2_session(session);
		return (result);
	}
	session->stream->postdata = message;
	session->stream->postdata_pos = 0;

	/* TODO do this properly!!! */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;
	host = strndup(
		&session->stream
			 ->uri[session->stream->u.field_data[UF_HOST].off],
		session->stream->u.field_data[UF_HOST].len);

	int s = getaddrinfo(host, NULL, &hints, &res);

	free(host);
	if (s != 0) {
		return (ISC_R_FAILURE);
	}

	isc_sockaddr_fromsockaddr(&peer, res->ai_addr);
	isc_sockaddr_setport(&peer, port);
	isc_sockaddr_anyofpf(&local, res->ai_family);

	freeaddrinfo(res);

	result = isc_nm_tlsconnect(mgr, (isc_nmiface_t *)&local,
				   (isc_nmiface_t *)&peer, connect_cb, session,
				   ctx, 0);

	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	return (ISC_R_SUCCESS);
}
