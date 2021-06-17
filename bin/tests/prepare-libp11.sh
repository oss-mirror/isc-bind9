#!/bin/sh -e

git clone https://github.com/OpenSC/libp11.git /var/tmp/libp11
cd /var/tmp/libp11
./bootstrap
./configure --with-enginesdir=/opt/bind9/engines
make
make install
cd ../../..
