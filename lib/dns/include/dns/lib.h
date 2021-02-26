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

#ifndef DNS_LIB_H
#define DNS_LIB_H 1

/*! \file dns/lib.h */

#include <isc/lang.h>
#include <isc/mem.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

/*%
 * Tuning: external query load in packets per seconds.
 */
LIBDNS_EXTERNAL_DATA extern unsigned int dns_pps;

/*%
 * Memory: global library memory context
 */
LIBDNS_EXTERNAL_DATA extern isc_mem_t *dns_g_mctx;

ISC_LANG_ENDDECLS

#endif /* DNS_LIB_H */
