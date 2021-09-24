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

if [ -z "$SOFTHSM2_MODULE" ] ; then
        echo_i "softhsm2 module not found, required for test"
        exit 1
fi

PWD=$(pwd)

keygen() {
	type="$1"
	bits="$2"
	zone="$3"
	id="$4"

	pkcs11-tool --module $SOFTHSM2_MODULE -l -k --key-type $type:$bits --label "${id}-${zone}" --pin $(cat $PWD/pin) || return 1
}

keyfromlabel() {
        alg="$1"
        zone="$2"
        id="$3"
        shift 3

	$KEYFRLAB -E pkcs11 -a $alg -l "token=keyfromlabel;object=${id}-${zone};pin-source=$PWD/pin" "$@" $zone || return 1
}

infile="template.db.in"
for algtypebits in rsasha256:rsa:2048 rsasha512:rsa:2048
		   # ecdsap256sha256:EC:prime256v1 ecdsap384sha384:EC:prime384v1
		   # ed25519:EC:edwards25519 # ed448:EC:edwards448
do
	alg=$(echo "$algtypebits" | cut -f 1 -d :)
	type=$(echo "$algtypebits" | cut -f 2 -d :)
	bits=$(echo "$algtypebits" | cut -f 3 -d :)

	if $SHELL ../testcrypto.sh $alg; then
		zone="$alg.example"
		zonefile="zone.$alg.example.db"
		ret=0

		echo_i "Generate keys $alg $type:$bits for zone $zone"
		keygen $type $bits $zone zsk || ret=1
		keygen $type $bits $zone ksk|| ret=1
		test "$ret" -eq 0 || echo_i "failed"
		status=$((status+ret))

		# Skip dnssec-keyfromlabel if key generation failed.
		test $ret == 0 || continue

		echo_i "Get ZSK $alg $id-$zone $type:$bits"
		ret=0
		zsk=$(keyfromlabel $alg $zone zsk)
		test -z "$zsk" && ret=1

		echo_i "Get KSK $alg $id-$zone $type:$bits"
		ret=0
		ksk=$(keyfromlabel $alg $zone ksk -f KSK)
		test -z "$ksk" && ret=1

		test "$ret" -eq 0 || echo_i "failed"
		status=$((status+ret))

		# Skip signing if dnssec-keyfromlabel failed.
		test $ret == 0 || continue

		echo_i "Sign zone with $ksk $zsk"
		ret=0
		cat "$infile" "$ksk.key" "$zsk.key" > "$zonefile"
		$SIGNER -E pkcs11 -S -a -g -o "$zone" "$zonefile" > /dev/null 2>&1 || ret=1
		test "$ret" -eq 0 || echo_i "failed"
		status=$((status+ret))
	fi
done

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
