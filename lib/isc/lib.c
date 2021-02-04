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
#include <isc/netmgr.h>
#include <isc/tls.h>
#include <isc/util.h>

/***
 *** Functions
 ***/

void
isc_lib_register(void) {
	isc_bind9 = false;
}

void
isc__initialize(void) ISC_CONSTRUCTOR(101);
void
isc__shutdown(void) ISC_DESTRUCTOR(101);

void
isc__initialize(void) {
	isc_mem_initialize(); /* Priority 102 */
	isc_tls_initialize(); /* Priority 103 */
	isc_nm_initialize();  /* Priority 104 */
}

void
isc__shutdown(void) {
	isc_nm_shutdown();  /* Priority 104 */
	isc_tls_shutdown(); /* Priority 103 */
	isc_mem_shutdown(); /* Priority 102 */
}
