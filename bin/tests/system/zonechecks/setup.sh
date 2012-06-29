#!/bin/sh
#
; Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
;
; Permission to use, copy, modify, and/or distribute this software for any
; purpose with or without fee is hereby granted, provided that the above
; copyright notice and this permission notice appear in all copies.
;
; THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
; REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
; AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
; INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
; LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
; OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
; PERFORMANCE OF THIS SOFTWARE.

# $Id: setup.sh,v 1.3 2012/01/31 23:47:32 tbox Exp $

sh clean.sh

../../../tools/genrandom 400 random.data
sh ../genzone.sh 1 > ns1/master.db
cd ns1
touch master.db.signed
echo '$INCLUDE "master.db.signed"' >> master.db
$KEYGEN -r ../random.data -3q master.example > /dev/null 2>&1
$KEYGEN -r ../random.data -3qfk master.example > /dev/null 2>&1
$SIGNER -SD -o master.example master.db > /dev/null 2>&1

