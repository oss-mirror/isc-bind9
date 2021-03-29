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

#ifndef ISC_RESULT_H
#define ISC_RESULT_H 1

/*! \file isc/result.h */

#include <isc/lang.h>
#include <isc/resultclass.h>
#include <isc/types.h>

/*
 * This file is generated at compile time from the result_*.h files
 * found in sibling library source directories.
 */
#include <isc/result_ext.h>

#define ISC_R_SUCCESS	   ISC_RESULTCODE_ISC(0)  /*%< success */
#define ISC_R_NOMEMORY	   ISC_RESULTCODE_ISC(1)  /*%< out of memory */
#define ISC_R_TIMEDOUT	   ISC_RESULTCODE_ISC(2)  /*%< timed out */
#define ISC_R_NOTHREADS	   ISC_RESULTCODE_ISC(3)  /*%< no available threads */
#define ISC_R_ADDRNOTAVAIL ISC_RESULTCODE_ISC(4)  /*%< address not available */
#define ISC_R_ADDRINUSE	   ISC_RESULTCODE_ISC(5)  /*%< address in use */
#define ISC_R_NOPERM	   ISC_RESULTCODE_ISC(6)  /*%< permission denied */
#define ISC_R_NOCONN	   ISC_RESULTCODE_ISC(7)  /*%< no pending connections */
#define ISC_R_NETUNREACH   ISC_RESULTCODE_ISC(8)  /*%< network unreachable */
#define ISC_R_HOSTUNREACH  ISC_RESULTCODE_ISC(9)  /*%< host unreachable */
#define ISC_R_NETDOWN	   ISC_RESULTCODE_ISC(10) /*%< network down */
#define ISC_R_HOSTDOWN	   ISC_RESULTCODE_ISC(11) /*%< host down */
#define ISC_R_CONNREFUSED  ISC_RESULTCODE_ISC(12) /*%< connection refused */
#define ISC_R_NORESOURCES \
	ISC_RESULTCODE_ISC(13) /*%< not enough free resources */
#define ISC_R_EOF	   ISC_RESULTCODE_ISC(14) /*%< end of file */
#define ISC_R_BOUND	   ISC_RESULTCODE_ISC(15) /*%< socket already bound */
#define ISC_R_RELOAD	   ISC_RESULTCODE_ISC(16) /*%< reload */
#define ISC_R_SUSPEND	   ISC_R_RELOAD		  /*%< alias of 'reload' */
#define ISC_R_LOCKBUSY	   ISC_RESULTCODE_ISC(17) /*%< lock busy */
#define ISC_R_EXISTS	   ISC_RESULTCODE_ISC(18) /*%< already exists */
#define ISC_R_NOSPACE	   ISC_RESULTCODE_ISC(19) /*%< ran out of space */
#define ISC_R_CANCELED	   ISC_RESULTCODE_ISC(20) /*%< operation canceled */
#define ISC_R_NOTBOUND	   ISC_RESULTCODE_ISC(21) /*%< socket is not bound */
#define ISC_R_SHUTTINGDOWN ISC_RESULTCODE_ISC(22) /*%< shutting down */
#define ISC_R_NOTFOUND	   ISC_RESULTCODE_ISC(23) /*%< not found */
#define ISC_R_UNEXPECTEDEND \
	ISC_RESULTCODE_ISC(24) /*%< unexpected end of input */
#define ISC_R_FAILURE	      ISC_RESULTCODE_ISC(25) /*%< generic failure */
#define ISC_R_IOERROR	      ISC_RESULTCODE_ISC(26) /*%< I/O error */
#define ISC_R_NOTIMPLEMENTED  ISC_RESULTCODE_ISC(27) /*%< not implemented */
#define ISC_R_UNBALANCED      ISC_RESULTCODE_ISC(28) /*%< unbalanced parentheses */
#define ISC_R_NOMORE	      ISC_RESULTCODE_ISC(29) /*%< no more */
#define ISC_R_INVALIDFILE     ISC_RESULTCODE_ISC(30) /*%< invalid file */
#define ISC_R_BADBASE64	      ISC_RESULTCODE_ISC(31) /*%< bad base64 encoding */
#define ISC_R_UNEXPECTEDTOKEN ISC_RESULTCODE_ISC(32) /*%< unexpected token */
#define ISC_R_QUOTA	      ISC_RESULTCODE_ISC(33) /*%< quota reached */
#define ISC_R_UNEXPECTED      ISC_RESULTCODE_ISC(34) /*%< unexpected error */
#define ISC_R_ALREADYRUNNING  ISC_RESULTCODE_ISC(35) /*%< already running */
#define ISC_R_IGNORE	      ISC_RESULTCODE_ISC(36) /*%< ignore */
#define ISC_R_MASKNONCONTIG \
	ISC_RESULTCODE_ISC(37) /*%< addr mask not contiguous */
#define ISC_R_FILENOTFOUND ISC_RESULTCODE_ISC(38) /*%< file not found */
#define ISC_R_FILEEXISTS   ISC_RESULTCODE_ISC(39) /*%< file already exists */
#define ISC_R_NOTCONNECTED \
	ISC_RESULTCODE_ISC(40)		       /*%< socket is not connected */
#define ISC_R_RANGE	ISC_RESULTCODE_ISC(41) /*%< out of range */
#define ISC_R_NOENTROPY ISC_RESULTCODE_ISC(42) /*%< out of entropy */
#define ISC_R_MULTICAST                                      \
	ISC_RESULTCODE_ISC(43) /*%< invalid use of multicast \
				*/
#define ISC_R_NOTFILE	   ISC_RESULTCODE_ISC(44) /*%< not a file */
#define ISC_R_NOTDIRECTORY ISC_RESULTCODE_ISC(45) /*%< not a directory */
#define ISC_R_QUEUEFULL	   ISC_RESULTCODE_ISC(46) /*%< queue is full */
#define ISC_R_FAMILYMISMATCH \
	ISC_RESULTCODE_ISC(47) /*%< address family mismatch */
#define ISC_R_FAMILYNOSUPPORT ISC_RESULTCODE_ISC(48) /*%< AF not supported */
#define ISC_R_BADHEX	      ISC_RESULTCODE_ISC(49) /*%< bad hex encoding */
#define ISC_R_TOOMANYOPENFILES \
	ISC_RESULTCODE_ISC(50)			 /*%< too many open files */
#define ISC_R_NOTBLOCKING ISC_RESULTCODE_ISC(51) /*%< not blocking */
#define ISC_R_UNBALANCEDQUOTES                                              \
	ISC_RESULTCODE_ISC(52)			     /*%< unbalanced quotes \
						      */
#define ISC_R_INPROGRESS      ISC_RESULTCODE_ISC(53) /*%< operation in progress */
#define ISC_R_CONNECTIONRESET ISC_RESULTCODE_ISC(54) /*%< connection reset */
#define ISC_R_SOFTQUOTA	      ISC_RESULTCODE_ISC(55) /*%< soft quota reached */
#define ISC_R_BADNUMBER	      ISC_RESULTCODE_ISC(56) /*%< not a valid number */
#define ISC_R_DISABLED	      ISC_RESULTCODE_ISC(57) /*%< disabled */
#define ISC_R_MAXSIZE	      ISC_RESULTCODE_ISC(58) /*%< max size */
#define ISC_R_BADADDRESSFORM \
	ISC_RESULTCODE_ISC(59)			/*%< invalid address format */
#define ISC_R_BADBASE32	 ISC_RESULTCODE_ISC(60) /*%< bad base32 encoding */
#define ISC_R_UNSET	 ISC_RESULTCODE_ISC(61) /*%< unset */
#define ISC_R_MULTIPLE	 ISC_RESULTCODE_ISC(62) /*%< multiple */
#define ISC_R_WOULDBLOCK ISC_RESULTCODE_ISC(63) /*%< would block */
#define ISC_R_COMPLETE	 ISC_RESULTCODE_ISC(64) /*%< complete */
#define ISC_R_CRYPTOFAILURE \
	ISC_RESULTCODE_ISC(65) /*%< cryptography library failure */
#define ISC_R_DISCQUOTA	 ISC_RESULTCODE_ISC(66) /*%< disc quota */
#define ISC_R_DISCFULL	 ISC_RESULTCODE_ISC(67) /*%< disc full */
#define ISC_R_DEFAULT	 ISC_RESULTCODE_ISC(68) /*%< default */
#define ISC_R_IPV4PREFIX ISC_RESULTCODE_ISC(69) /*%< IPv4 prefix */
#define ISC_R_TLSERROR	 ISC_RESULTCODE_ISC(70) /*%< TLS error */
#define ISC_R_HTTP2ALPNERROR \
	ISC_RESULTCODE_ISC(71) /*%< ALPN for HTTP/2 failed */

/*% Not a result code: the number of results. */
#define ISC_R_NRESULTS 72

ISC_LANG_BEGINDECLS

const char *isc_result_totext(isc_result_t);
/*%<
 * Convert an isc_result_t into a string message describing the result.
 */

const char *isc_result_toid(isc_result_t);
/*%<
 * Convert an isc_result_t into a string identifier such as
 * "ISC_R_SUCCESS".
 */

ISC_LANG_ENDDECLS

#endif /* ISC_RESULT_H */
