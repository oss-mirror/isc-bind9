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

# shellcheck source=conf.sh
. ../conf.sh

set -e

if [ -z "$SOFTHSM2_CONF" ] ; then
	echo_i "softhsm2 configuration not set, required for test"
	exit 1
fi

if [ -z "$SOFTHSM2_MODULE" ] ; then
	echo_i "softhsm2 module not set, required for test"
	exit 1
fi

if [ -z "$OPENSSL_ENGINES" ] ; then
	echo_i "openssl engines path not set, required for test"
	exit 1
fi

printf '%s' "${HSMPIN:-1234}" > pin
PWD=$(pwd)

echo_i "What's in $SSLCNF?"

cat $SSLCNF

if [ -f "/var/tmp/engines/pkcs11.so" ]; then
	echo_i "dynamic_path pkcs11.so ok"
else
	echo_i "pkcs11.so not found, required for test"
	exit 1
fi

if [ -f "$SOFTHSM2_MODULE" ] ; then
	echo_i "softhsm2 module not found, required for test"
	exit 1
fi

echo_i "Initialize softhsm2 token..."

softhsm2-util --init-token --free --pin $(cat $PWD/pin) --so-pin $(cat $PWD/pin) --label "keyfromlabel"
