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

#include <uv.h>

#include <isc/bind9.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/util.h>

/***
 *** Functions
 ***/

void
isc_lib_register(void) {
	isc_bind9 = false;
}

LIBISC_EXTERNAL_DATA extern isc_mem_t *isc__mem_mctx;

void
isc__mem_initialize(void) ISC_CONSTRUCTOR(101);
void
isc__mem_shutdown(void) ISC_DESTRUCTOR(101);

void
isc__mem_initialize(void) {
	REQUIRE(isc__mem_mctx == NULL);
	isc_mem_create(&isc__mem_mctx);
	isc_mem_setname(isc__mem_mctx, "default");
}

void
isc__mem_shutdown(void) {
	REQUIRE(isc__mem_mctx != NULL);
	isc_mem_destroy(&isc__mem_mctx);
	/* FIXME: All code using raw 'exit(1);' has to be fixed first */
	/* isc_mem_checkdestroyed(stderr); */
}

void
isc__nm_initialize(void) ISC_CONSTRUCTOR(102);
void
isc__nm_shutdown(void) ISC_DESTRUCTOR(102);

#if UV_VERSION_MAJOR > 1 || (UV_VERSION_MAJOR == 1 && UV_VERSION_MINOR >= 38)

static void *
_malloc(size_t size) {
	return (isc_malloc(size));
}

static void *
_calloc(size_t num, size_t size) {
	return (isc_calloc(num, size));
}

static void *
_realloc(void *ptr, size_t size) {
	return (isc_realloc(ptr, size));
}

static void
_free(void *ptr) {
	return (isc_free(ptr));
}

void
isc__nm_initialize(void) {
	uv_replace_allocator(_malloc, _realloc, _calloc, _free);
}

void
isc__nm_shutdown(void) {
	uv_library_shutdown();
}

#else

void
isc__nm_initialize(void) {}

void
isc__nm_shutdown(void) {}

#endif
