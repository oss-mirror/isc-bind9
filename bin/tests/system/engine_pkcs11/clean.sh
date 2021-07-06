#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

set -e

rm -f K* ns1/K* keyset-* dsset-*
rm -f ns1/named.conf ns1/*.db ns1/*.signed ns1/*.jnl
rm -f dig.out* pin supported
rm -f ns1/*.ksk ns1/*.zsk ns1/named.memstats
rm -f ns*/named.run ns*/named.lock ns*/named.conf
rm -f ns*/managed-keys.bind*