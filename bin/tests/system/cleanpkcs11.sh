#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

. "$SYSTEMTESTTOP/conf.sh"

PK11DELBIN=$(echo "$PK11DEL" | awk '{ print $1 }')

[ -x "$PK11DELBIN" ] && $PK11DEL -w0 > /dev/null 2>&1
