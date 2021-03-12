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
