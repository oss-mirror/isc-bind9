/*
 * Copyright (C) 2000, 2001, 2004, 2007, 2009, 2015, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: ntpaths.h,v 1.20 2009/07/14 22:54:57 each Exp $ */

/*
 * Windows-specific path definitions
 * These routines are used to set up and return system-specific path
 * information about the files enumerated in NtPaths
 */

#ifndef ISC_NTPATHS_H
#define ISC_NTPATHS_H

#include <isc/lang.h>

/*
 * Index of paths needed
 */
enum NtPaths {
	NAMED_CONF_PATH,
	LWRES_CONF_PATH,
	RESOLV_CONF_PATH,
	RNDC_CONF_PATH,
	NAMED_PID_PATH,
	LWRESD_PID_PATH,
	NAMED_LOCK_PATH,
	LOCAL_STATE_DIR,
	SYS_CONF_DIR,
	RNDC_KEY_PATH,
	SESSION_KEY_PATH
};

/*
 * Define macros to get the path of the config files
 */
#define NAMED_CONFFILE isc_ntpaths_get(NAMED_CONF_PATH)
#define RNDC_CONFFILE isc_ntpaths_get(RNDC_CONF_PATH)
#define RNDC_KEYFILE isc_ntpaths_get(RNDC_KEY_PATH)
#define SESSION_KEYFILE isc_ntpaths_get(SESSION_KEY_PATH)
#define RESOLV_CONF isc_ntpaths_get(RESOLV_CONF_PATH)

/*
 * Information about where the files are on disk
 */
#define NS_LOCALSTATEDIR	"/dns/bin"
#define NS_SYSCONFDIR		"/dns/etc"

ISC_LANG_BEGINDECLS

void
isc_ntpaths_init(void);

char *
isc_ntpaths_get(int);

ISC_LANG_ENDDECLS

#endif /* ISC_NTPATHS_H */
