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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/mutex.h>
#include <isc/netmgr.h>
#include <isc/nonce.h>
#include <isc/os.h>
#include <isc/refcount.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>

#include "uv_wrap.h"
#define KEEP_BEFORE

#include "../netmgr/netmgr-int.h"
#include "../netmgr/udp.c"
#include "../netmgr/uv-compat.c"
#include "../netmgr/uv-compat.h"
#include "isctest.h"

static isc_sockaddr_t udp_listen_addr;

static unsigned int workers = 4;

static int
setup_ephemeral_port(isc_sockaddr_t *addr, sa_family_t family) {
	isc_result_t result;
	socklen_t addrlen = sizeof(*addr);
	int fd;
	int r;

	isc_sockaddr_fromin6(addr, &in6addr_any, 0);
	isc_sockaddr_setport(addr, 53);

	fd = socket(AF_INET6, family, 0);
	if (fd < 0) {
		perror("setup_ephemeral_port: socket()");
		return (-1);
	}

	result = isc__nm_socket_reuse(fd);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTIMPLEMENTED) {
		fprintf(stderr,
			"setup_ephemeral_port: isc__nm_socket_reuse(): %s",
			isc_result_totext(result));
		close(fd);
		return (-1);
	}

	r = bind(fd, (const struct sockaddr *)&addr->type.sa,
		 sizeof(addr->type.sin6));
	if (r != 0) {
		perror("setup_ephemeral_port: bind()");
		close(fd);
		return (r);
	}

	r = getsockname(fd, (struct sockaddr *)&addr->type.sa, &addrlen);
	if (r != 0) {
		perror("setup_ephemeral_port: getsockname()");
		close(fd);
		return (r);
	}

	result = isc__nm_socket_reuse_lb(fd);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTIMPLEMENTED) {
		fprintf(stderr,
			"setup_ephemeral_port: isc__nm_socket_reuse_lb(): %s",
			isc_result_totext(result));
		close(fd);
		return (-1);
	}

#if IPV6_RECVERR
#define setsockopt_on(socket, level, name) \
	setsockopt(socket, level, name, &(int){ 1 }, sizeof(int))

	r = setsockopt_on(fd, IPPROTO_IPV6, IPV6_RECVERR);
	if (r != 0) {
		perror("setup_ephemeral_port");
		close(fd);
		return (r);
	}
#endif

	return (fd);
}

static int
nm_setup(isc_nm_t **nmp) {
	int udp_listen_sock = -1;
	isc_nm_t *nm = NULL;

	udp_listen_addr = (isc_sockaddr_t){ .length = 0 };
	udp_listen_sock = setup_ephemeral_port(&udp_listen_addr, SOCK_DGRAM);
	if (udp_listen_sock < 0) {
		return (-1);
	}
	close(udp_listen_sock);
	udp_listen_sock = -1;

	nm = isc_mem_get(test_mctx, sizeof(nm));
	nm = isc_nm_start(test_mctx, workers);
	assert_non_null(nm);

	*nmp = nm;

	return (0);
}

static int
nm_teardown(isc_nm_t **nmp) {
	isc_nm_t *nm = *nmp;

	isc_nm_destroy(&nm);
	assert_null(nm);
	isc_mem_put(test_mctx, nm, sizeof(nm));

	return (0);
}

static void
udp_listen_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	assert_non_null(handle);
	isc_region_t *reply = cbarg;

	if (eresult != ISC_R_SUCCESS) {
		printf("%s failure: %d\n", __func__, eresult);
	}
	isc_mem_put(handle->sock->mgr->mctx, cbarg, sizeof(isc_region_t) + reply->length);
}

static void
udp_listen_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	assert_null(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("%s failure: %d\n", __func__, eresult);
		return;
	}

	if(region->length >= 12) {
		/* long enough to be a DNS header, set QR bit */
		((uint8_t *)region->base)[2] ^= 0x80;
	}

	isc_region_t *reply = isc_mem_get(handle->sock->mgr->mctx, sizeof(isc_region_t) + region->length);
	assert_non_null(reply);
	reply->length = region->length;
	reply->base = (uint8_t *)reply + sizeof(isc_region_t);
	memmove(reply->base, region->base, region->length);
	isc_nm_send(handle, reply, udp_listen_send_cb, reply);
}

static void
udp_recv_send(isc_nm_t **nmp) {
	isc_nm_t *listen_nm = *nmp;
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;

	result = isc_nm_listenudp(listen_nm, (isc_nmiface_t *)&udp_listen_addr,
				  udp_listen_recv_cb, NULL, 0, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	while(true) /* TODO */
		usleep(100000000);

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);
}

int
main(int argc, char **argv) {
	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 1;
	printf("workers = %d\n", workers);
	if (isc_test_begin(NULL, true, workers) != ISC_R_SUCCESS) {
		return (-1);
	}

	signal(SIGPIPE, SIG_IGN);

	isc_nm_t *nm = NULL;
	if(nm_setup(&nm)) {
		printf("network setup failed, exiting\n");
		return 1;
	}
	udp_recv_send(&nm);
	nm_teardown(&nm);
	isc_test_end();
	return (0);
}
