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

#ifndef DNS_RESULT_H
#define DNS_RESULT_H 1

/*! \file dns/result.h */

#include <isc/lang.h>
#include <isc/resultclass.h>

#include <dns/types.h>

/*
 * Nothing in this file truly depends on <isc/result.h>, but the
 * DNS result codes are considered to be publicly derived from
 * the ISC result codes, so including this file buys you the ISC_R_
 * namespace too.
 */
#include <isc/result.h> /* Contractual promise. */

#define DNS_RESULT_ISRCODE(result) \
	(ISC_RESULTCLASS_INCLASS(ISC_RESULTCLASS_DNSRCODE, (result)))

ISC_LANG_BEGINDECLS

dns_rcode_t
dns_result_torcode(isc_result_t result);

ISC_LANG_ENDDECLS

#endif /* DNS_RESULT_H */
