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

#include <stdbool.h>
#include <stddef.h>

#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/lib.h>
#include <dns/result.h>

#include <dst/dst.h>

#include "dispatch_p.h"
#include "lib_p.h"
#include "message_p.h"

/***
 *** Globals
 ***/

LIBDNS_EXTERNAL_DATA unsigned int dns_pps = 0U;
LIBDNS_EXTERNAL_DATA isc_mem_t *dns_g_mctx = NULL;

/***
 *** Functions
 ***/

void
dns__initialize(void) {
	isc_mem_create(&dns_g_mctx);

	dns__message_initialize();
	dns__dispatch_initialize();

	dns_result_register();
}

void
dns__shutdown(void) {
	dns__dispatch_shutdown();
	dns__message_shutdown();
	isc_mem_detach(&dns_g_mctx);
}
