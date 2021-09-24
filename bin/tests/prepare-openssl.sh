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

# Installing OpenSC
apt-get -y install opensc

git clone https://github.com/OpenSC/libp11.git /var/tmp/libp11
cd /var/tmp/libp11
./bootstrap
./configure --with-enginesdir=${ENGINES_DIR}
make
make install
cd ../../..

# Configuring OpenSSL
OPENSSL_DIR=$(dirname "$OPENSSL_CONF")
mkdir -p ${OPENSSL_DIR}
echo 'openssl_conf = openssl_init' > ${OPENSSL_CONF}
# grep -v "openssl_conf = " ${SSLCNF} >> ${OPENSSL_CONF}
cat ${SSLCNF} >> ${OPENSSL_CONF}
cat >> ${OPENSSL_CONF} <<EOF

[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = "${ENGINES_DIR}/pkcs11.so"
MODULE_PATH = "${SOFTHSM2_MODULE}"
init = 0
EOF

cp ${OPENSSL_CONF} ${SSLCNF}
exit 0
