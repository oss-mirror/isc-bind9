#!/bin/sh -e

# OpenSC/libp11
git clone https://github.com/OpenSC/libp11.git /var/tmp/libp11
cd /var/tmp/libp11
./bootstrap
./configure --with-enginesdir=/opt/bind9/engines
make
make install
cd ../../..

# OpenSC/OpenSC
git clone git://github.com/OpenSC/OpenSC.git /var/tmp/OpenSC
cd /var/tmp/OpenSC
./bootstrap
./configure --prefix=/usr --sysconfdir=/etc/opensc
make
make install
cd ../../../
