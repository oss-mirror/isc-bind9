#!/bin/sh -e

mkdir -p /var/tmp/openssl/
echo 'openssl_conf = openssl_init' > /var/tmp/openssl/openssl.cnf
cat /etc/ssl/openssl.cnf >> /var/tmp/openssl/openssl.cnf
cat >> /var/tmp/openssl/openssl.cnf <<EOF
[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /opt/bind9/engines/pkcs11.so
MODULE_PATH = /usr/lib/softhsm/libsofthsm2.so
init = 0
EOF
