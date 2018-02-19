/*
 * Copyright (C) 2002, 2004-2007, 2009, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: netscope.h,v 1.13 2009/06/25 23:48:02 tbox Exp $ */

#ifndef ISC_NETSCOPE_H
#define ISC_NETSCOPE_H 1

/*! \file isc/netscope.h */

ISC_LANG_BEGINDECLS

/*%
 * Convert a string of an IPv6 scope zone to zone index.  If the conversion
 * succeeds, 'zoneid' will store the index value.
 *
 * XXXJT: when a standard interface for this purpose is defined,
 * we should use it.
 *
 * Returns:
 * \li	ISC_R_SUCCESS: conversion succeeds
 * \li	ISC_R_FAILURE: conversion fails
 */
isc_result_t
isc_netscope_pton(int af, char *scopename, void *addr, isc_uint32_t *zoneid);

ISC_LANG_ENDDECLS

#endif /* ISC_NETSCOPE_H */
