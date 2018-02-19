/*
 * Copyright (C) 1999-2002, 2004, 2005, 2007, 2009, 2013, 2015, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef NAMED_MAIN_H
#define NAMED_MAIN_H 1

/*! \file */

#ifdef ISC_MAIN_HOOK
#define main(argc, argv) bindmain(argc, argv)
#endif

/*
 * Commandline arguments for named; also referenced in win32/ntservice.c
 */
#define NS_MAIN_ARGS "46A:c:C:d:D:E:fFgi:lL:M:m:n:N:p:P:sS:t:T:U:u:vVx:X:"

ISC_PLATFORM_NORETURN_PRE void
ns_main_earlyfatal(const char *format, ...)
ISC_FORMAT_PRINTF(1, 2) ISC_PLATFORM_NORETURN_POST;

void
ns_main_earlywarning(const char *format, ...) ISC_FORMAT_PRINTF(1, 2);

void
ns_main_setmemstats(const char *);

#endif /* NAMED_MAIN_H */
