/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#ifndef DNS_CONFIG_CONFPVT_H
#define DNS_CONFIG_CONFPVT_H 1

/*****
 ***** Module Info
 *****/

/*
 * Some private definitions for config module internal use.
 */

/*
 * Various structures keep track of whether fields have been assigned
 * to. They do this with a bit field.
 */
#define DNS_C_SETBITS_SIZE	(sizeof(dns_setbits_t) * 8)
#define DNS_C_SETBIT(bit, flags) \
     (*(flags) |= ((dns_setbits_t)1 << (bit)))
#define DNS_C_CLEARBIT(bit, flags) \
     (*(flags) &= ~((dns_setbits_t)1 << (bit)))
#define DNS_C_CHECKBIT(bit,flags) \
     ((*(flags) & ((dns_setbits_t)1 << (bit))) == ((dns_setbits_t)1 << (bit)))

#define DNS_C_VALID_STRUCT(p,m)		((p) != NULL && (p)->magic == m)



#endif
