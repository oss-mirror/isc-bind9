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

#include <stdio.h>
#include <windows.h>

#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/tls.h>

/*
 * Called when we enter the DLL
 */
__declspec(dllexport) BOOL WINAPI
	DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
	/*
	 * The DLL is loading due to process initialization or a call to
	 * LoadLibrary.
	 */
	case DLL_PROCESS_ATTACH:
		/*
		 * Disable DllMain() invocation on Thread creation/destruction
		 */
		DisableThreadLibraryCalls(hinstDLL);
		isc_mem_initialize(); /* priority=101 */
		isc_tls_initialize(); /* priority=102
		isc_nm_initialized(); /* priority=103 */
		break;

	/*
	 * The DLL is unloading from a process due to process
	 * termination or a call to FreeLibrary.
	 */
	case DLL_PROCESS_DETACH:
		isc_nm_shutdown();  /* priority=103 */
		isc_tls_shutdown(); /* priority=102 */
		isc_mem_shutdown(); /* priority=101 */
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		/*
		 * Calling DllMain when attaching/detaching process has been
		 * disabled.
		 */
		INSIST(0);
		break;

	default:
		break;
	}
	return (TRUE);
}
