/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Principal Author: Bob Halley
 */

#include <config.h>

#include <isc/assertions.h>
#include <isc/event.h>
#include <isc/mem.h>

/***
 *** Events.
 ***/

static void
destroy(isc_event_t *event) {
	isc_mem_t *mctx = event->ev_destroy_arg;

	isc_mem_put(mctx, event, event->ev_size);
}

isc_event_t *
isc_event_allocate(isc_mem_t *mctx, void *sender, isc_eventtype_t type,
		   isc_taskaction_t action, void *arg, size_t size)
{
	isc_event_t *event;

	if (size < sizeof (struct isc_event))
		return (NULL);
	if (action == NULL)
		return (NULL);

	event = isc_mem_get(mctx, size);
	if (event == NULL)
		return (NULL);
	ISC_EVENT_INIT(event, size, 0, NULL, type, action, arg, sender,
		       destroy, mctx);

	return (event);
}

void
isc_event_free(isc_event_t **eventp) {
	isc_event_t *event;
	
	REQUIRE(eventp != NULL);
	event = *eventp;
	REQUIRE(event != NULL);

	if (event->ev_destroy != NULL)
		(event->ev_destroy)(event);

	*eventp = NULL;
}
