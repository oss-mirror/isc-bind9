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

$SHELL clean.sh

echo_i "Generating keys for engine_pkcs11 PKCS#11"

infile=ns1/example.db.in

printf '%s' "${HSMPIN:-1234}" > pin
PWD=$(pwd)
PKCS11TOOL="pkcs11-tool"

copy_setports ns1/named.conf.in ns1/named.conf

keygen() {
	type="$2"
	bits="$3"
	zone="$4"

	module="/usr/lib/softhsm/libsofthsm2.so"
	$PKCS11TOOL --module $module -l -k --key-type $type:$bits --label "${zone}-${id}" --pin $(cat $PWD/pin)
}

keyfromlabel() {
	alg="$1"
	zone="$4"
	id="$5"
	shift 5
	$KEYFRLAB -E pkcs11 -a "$alg" -l "token=softhsm2;object=${zone}-${id};pin-source=$PWD/pin" "$@" "$zone"
}

genksk() {
	keygen "$@"
	keyfromlabel "$@" -f KSK
}

genzsk() {
	keygen "$@"
	keyfromlabel "$@"
}

algs=
for algtypebits in rsasha256:rsa:2048 rsasha512:rsa:2048 \
		   ecdsap256sha256:EC:prime256v1 ecdsap384sha384:EC:prime384v1 \
		   ed25519:edwards25519:256 ed448:edwards448:456
do
	alg=$(echo "$algtypebits" | cut -f 1 -d :)
	type=$(echo "$algtypebits" | cut -f 2 -d :)
	bits=$(echo "$algtypebits" | cut -f 3 -d :)
	zone="$alg.example"
	zonefile="ns1/$alg.example.db"
	if $SHELL "../testcrypto.sh" "$alg"; then
		echo "$alg" >> supported
		algs="$algs$alg "

		zsk1=$(genzsk "$alg" "$type" "$bits" "$zone" "zsk1")
		zsk2=$(genzsk "$alg" "$type" "$bits" "$zone" "zsk2")
		ksk1=$(genksk "$alg" "$type" "$bits" "$zone" "ksk1")
		ksk2=$(genksk "$alg" "$type" "$bits"  "$zone" "ksk2")

		cat "$infile" "$zsk1.key" "$ksk1.key" > "$zonefile"
		$SIGNER -E pkcs11 -a -P -g -o "$zone" "$zonefile" > /dev/null
		cp "$zsk2.key" "ns1/$alg.zsk"
		cp "$ksk2.key" "ns1/$alg.ksk"
		mv "K$alg"* ns1/

		cat >> ns1/named.conf <<EOF
zone "$alg.example." {
        type primary;
        file "$alg.example.db.signed";
        allow-update { any; };
};

EOF
	fi
done
echo_i "Generated keys for engine_pkcs11 PKCS#11: $algs"
