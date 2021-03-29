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

#include <stddef.h>
#include <stdlib.h>

#include <isc/lib.h>
#include <isc/resultclass.h>
#include <isc/util.h>

/*
 * This file is generated at compile time from the result_*.c files
 * found in sibling library source directories:
 */
#include "result_ext.c"

static const char *isc_result_descriptions[ISC_R_NRESULTS] = {
	"success",			    /*%< 0 */
	"out of memory",		    /*%< 1 */
	"timed out",			    /*%< 2 */
	"no available threads",		    /*%< 3 */
	"address not available",	    /*%< 4 */
	"address in use",		    /*%< 5 */
	"permission denied",		    /*%< 6 */
	"no pending connections",	    /*%< 7 */
	"network unreachable",		    /*%< 8 */
	"host unreachable",		    /*%< 9 */
	"network down",			    /*%< 10 */
	"host down",			    /*%< 11 */
	"connection refused",		    /*%< 12 */
	"not enough free resources",	    /*%< 13 */
	"end of file",			    /*%< 14 */
	"socket already bound",		    /*%< 15 */
	"reload",			    /*%< 16 */
	"lock busy",			    /*%< 17 */
	"already exists",		    /*%< 18 */
	"ran out of space",		    /*%< 19 */
	"operation canceled",		    /*%< 20 */
	"socket is not bound",		    /*%< 21 */
	"shutting down",		    /*%< 22 */
	"not found",			    /*%< 23 */
	"unexpected end of input",	    /*%< 24 */
	"failure",			    /*%< 25 */
	"I/O error",			    /*%< 26 */
	"not implemented",		    /*%< 27 */
	"unbalanced parentheses",	    /*%< 28 */
	"no more",			    /*%< 29 */
	"invalid file",			    /*%< 30 */
	"bad base64 encoding",		    /*%< 31 */
	"unexpected token",		    /*%< 32 */
	"quota reached",		    /*%< 33 */
	"unexpected error",		    /*%< 34 */
	"already running",		    /*%< 35 */
	"ignore",			    /*%< 36 */
	"address mask not contiguous",	    /*%< 37 */
	"file not found",		    /*%< 38 */
	"file already exists",		    /*%< 39 */
	"socket is not connected",	    /*%< 40 */
	"out of range",			    /*%< 41 */
	"out of entropy",		    /*%< 42 */
	"invalid use of multicast address", /*%< 43 */
	"not a file",			    /*%< 44 */
	"not a directory",		    /*%< 45 */
	"queue is full",		    /*%< 46 */
	"address family mismatch",	    /*%< 47 */
	"address family not supported",	    /*%< 48 */
	"bad hex encoding",		    /*%< 49 */
	"too many open files",		    /*%< 50 */
	"not blocking",			    /*%< 51 */
	"unbalanced quotes",		    /*%< 52 */
	"operation in progress",	    /*%< 53 */
	"connection reset",		    /*%< 54 */
	"soft quota reached",		    /*%< 55 */
	"not a valid number",		    /*%< 56 */
	"disabled",			    /*%< 57 */
	"max size",			    /*%< 58 */
	"invalid address format",	    /*%< 59 */
	"bad base32 encoding",		    /*%< 60 */
	"unset",			    /*%< 61 */
	"multiple",			    /*%< 62 */
	"would block",			    /*%< 63 */
	"complete",			    /*%< 64 */
	"crypto failure",		    /*%< 65 */
	"disc quota",			    /*%< 66 */
	"disc full",			    /*%< 67 */
	"default",			    /*%< 68 */
	"IPv4 prefix",			    /*%< 69 */
	"TLS error",			    /*%< 70 */
	"ALPN for HTTP/2 failed"	    /*%< 71 */
};

static const char *isc_result_ids[ISC_R_NRESULTS] = { "ISC_R_SUCCESS",
						      "ISC_R_NOMEMORY",
						      "ISC_R_TIMEDOUT",
						      "ISC_R_NOTHREADS",
						      "ISC_R_ADDRNOTAVAIL",
						      "ISC_R_ADDRINUSE",
						      "ISC_R_NOPERM",
						      "ISC_R_NOCONN",
						      "ISC_R_NETUNREACH",
						      "ISC_R_HOSTUNREACH",
						      "ISC_R_NETDOWN",
						      "ISC_R_HOSTDOWN",
						      "ISC_R_CONNREFUSED",
						      "ISC_R_NORESOURCES",
						      "ISC_R_EOF",
						      "ISC_R_BOUND",
						      "ISC_R_RELOAD",
						      "ISC_R_LOCKBUSY",
						      "ISC_R_EXISTS",
						      "ISC_R_NOSPACE",
						      "ISC_R_CANCELED",
						      "ISC_R_NOTBOUND",
						      "ISC_R_SHUTTINGDOWN",
						      "ISC_R_NOTFOUND",
						      "ISC_R_UNEXPECTEDEND",
						      "ISC_R_FAILURE",
						      "ISC_R_IOERROR",
						      "ISC_R_NOTIMPLEMENTED",
						      "ISC_R_UNBALANCED",
						      "ISC_R_NOMORE",
						      "ISC_R_INVALIDFILE",
						      "ISC_R_BADBASE64",
						      "ISC_R_UNEXPECTEDTOKEN",
						      "ISC_R_QUOTA",
						      "ISC_R_UNEXPECTED",
						      "ISC_R_ALREADYRUNNING",
						      "ISC_R_IGNORE",
						      "ISC_R_MASKNONCONTIG",
						      "ISC_R_FILENOTFOUND",
						      "ISC_R_FILEEXISTS",
						      "ISC_R_NOTCONNECTED",
						      "ISC_R_RANGE",
						      "ISC_R_NOENTROPY",
						      "ISC_R_MULTICAST",
						      "ISC_R_NOTFILE",
						      "ISC_R_NOTDIRECTORY",
						      "ISC_R_QUEUEFULL",
						      "ISC_R_FAMILYMISMATCH",
						      "ISC_R_FAMILYNOSUPPORT",
						      "ISC_R_BADHEX",
						      "ISC_R_TOOMANYOPENFILES",
						      "ISC_R_NOTBLOCKING",
						      "ISC_R_UNBALANCEDQUOTES",
						      "ISC_R_INPROGRESS",
						      "ISC_R_CONNECTIONRESET",
						      "ISC_R_SOFTQUOTA",
						      "ISC_R_BADNUMBER",
						      "ISC_R_DISABLED",
						      "ISC_R_MAXSIZE",
						      "ISC_R_BADADDRESSFORM",
						      "ISC_R_BADBASE32",
						      "ISC_R_UNSET",
						      "ISC_R_MULTIPLE",
						      "ISC_R_WOULDBLOCK",
						      "ISC_R_COMPLETE",
						      "ISC_R_CRYPTOFAILURE",
						      "ISC_R_DISCQUOTA",
						      "ISC_R_DISCFULL",
						      "ISC_R_DEFAULT",
						      "ISC_R_IPV4PREFIX",
						      "ISC_R_TLSERROR",
						      "ISC_R_HTTP2ALPNERROR" };

static struct {
	size_t nresults; /*%< total number of result codes in this class */
	const char **description_table; /*%< brief description of the result */
	const char **id_table;		/*%< result id, e.g. ISC_R_NOPERM */
} const result_classes[ISC_RESULTCLASS_MAX + 1] = {
	[ISC_RESULTCLASS_ISC] = { ISC_R_NRESULTS, isc_result_descriptions,
				  isc_result_ids },
	[ISC_RESULTCLASS_DNS] = { DNS_R_NRESULTS, dns_result_descriptions,
				  dns_result_ids },
	[ISC_RESULTCLASS_DST] = { DST_R_NRESULTS, dst_result_descriptions,
				  dst_result_ids },
	[ISC_RESULTCLASS_DNSRCODE] = { DNS_R_NRCODERESULTS,
				       dns_rcode_descriptions, dns_rcode_ids },
	[ISC_RESULTCLASS_ISCCC] = { ISCCC_R_NRESULTS, isccc_result_descriptions,
				    isccc_result_ids },
	[ISC_RESULTCLASS_PK11] = { PK11_R_NRESULTS, pk11_result_descriptions,
				   pk11_result_ids }
};

static inline const char *
isc_result_from_table(isc_result_t result, bool description) {
	uint32_t rclass = ISC_RESULT_CLASS(result);
	uint32_t rindex = ISC_RESULT_VALUE(result);

	REQUIRE(rclass <= ISC_RESULTCLASS_MAX);

	if (rindex < result_classes[rclass].nresults) {
		return (description ? result_classes[rclass]
					      .description_table[rindex]
				    : result_classes[rclass].id_table[rindex]);
	}

	return ("(result code text not available)");
}

const char *
isc_result_totext(isc_result_t result) {
	return (isc_result_from_table(result, true));
}

const char *
isc_result_toid(isc_result_t result) {
	return (isc_result_from_table(result, false));
}
