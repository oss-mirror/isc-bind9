.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

..
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.

   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

.. _bind9.library:

BIND 9 DNS Library Support
==========================

This version of BIND 9 "exports" its internal libraries ("export libraries") so that they can
be used by third-party applications more easily. Certain library functions are altered from
specific BIND-only behavior to more generic behavior when used by other
applications; to enable this generic behavior, the calling program
initializes the libraries by calling ``isc_lib_register()``.

In addition to DNS-related APIs that are used within BIND 9, the
libraries provide the following features:

-  The "DNS client" module is a higher-level API that provides an
   interface to name resolution, single DNS transactions with a
   particular server, and dynamic update. In terms of name resolution, it
   supports advanced features such as DNSSEC validation and caching.
   This module supports both synchronous and asynchronous modes.

-  The "IRS" (Information Retrieval System) library provides an
   interface to parse both the traditional ``resolv.conf`` file and a more
   advanced, DNS-specific configuration file for the rest of this
   package (see the description for the ``dns.conf`` file below).

-  As part of the IRS library, the standard address-name mapping
   functions, ``getaddrinfo()`` and ``getnameinfo()``, are provided.
   They use the DNSSEC-aware validating resolver backend, and can use
   other advanced features of the BIND 9 libraries, such as caching. The
   ``getaddrinfo()`` function resolves both A and AAAA RRs concurrently
   when the address family is unspecified.

-  An experimental framework to support other event libraries than BIND
   9's internal event task system is also available.

Installation
------------

::

   $ make install


Normal installation of BIND also installs library objects and header
files. Root privilege is normally required.

For instructions on building the application after installation, see
``lib/samples/Makefile-postinstall.in``.

Known Defects/Restrictions
--------------------------

-  The "fixed" RRset order is not currently supported in the export
   library. To use "fixed" RRset order for, e.g., ``named``
   while still building the export library without the fixed order
   support, build them separately:

   ::

      $ ./configure --enable-fixed-rrset [other flags, but not --enable-exportlib]
      $ make
      $ ./configure --enable-exportlib [other flags, but not --enable-fixed-rrset]
      $ cd lib/export
      $ make

-  :rfc:`5011` is not supported in the validating stub resolver of the
   export library. In fact, it is not clear whether it should be: trust
   anchors would be a system-wide configuration to be managed
   by an administrator, while the stub resolver is used by ordinary
   applications run by a normal user.

-  Not all common ``/etc/resolv.conf`` options are supported in the IRS
   library. The only available options in this version are ``debug`` and
   ``ndots``.

The ``dns.conf`` File
---------------------

The IRS library supports an "advanced" configuration file, related to the
DNS library, for configuration parameters that would be beyond the
capability of the ``resolv.conf`` file. Specifically, it is intended to
provide DNSSEC-related configuration parameters. By default the path to
this configuration file is ``/etc/dns.conf``. This module is very
experimental and the configuration syntax or library interfaces may
change in future versions. Currently, only the ``trusted-keys``
statement is supported, whose syntax is the same as the same statement
in ``named.conf``. (See :ref:`trusted-keys` for details.)

Sample Applications
-------------------

Some sample application programs using this API are provided for
reference. The following is a brief description of these applications.

``sample``: a Simple Stub Resolver Utility
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sends a query of a given name (of a given optional RR type) to a
specified recursive server and prints the result as a list of RRs. It
can also act as a validating stub resolver if a trust anchor is given
via a set of command line options.

Usage:

::

   sample [options] server_address hostname

Options and arguments:

``-t RRtype``
   This specifies the RR type of the query. The default is the A RR.

``[-a algorithm] [-e] [-k keyname] [-K keystring]``
   This specifies a command-line DNS key to validate the answer. For example,
   to specify the following DNSKEY of ``example.com: example.com. 3600 IN
   DNSKEY 257 3 5 xxx``, specify the options as follows:

::

   -e -k example.com -K "xxx"


   -e indicates that this key is a zone's key-signing key (also known as
   "secure entry point"). When -a is omitted, rsasha1 is used by
   default.

``-s domain:alt_server_address``
   This specifies a separate recursive server address for the specific
   domain. For example: ``-s example.com:2001:db8::1234``.

``server_address``
   This specifies the IP(v4/v6) address of the recursive server to which queries are
   sent.

``hostname``
   This indicates the domain name for the query.

``sample-async``: a Simple Stub Resolver, Working synchronously
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This application is similar to ``sample``, but it accepts a list of (query) domain names as a
separate file and resolves the names asynchronously.

Usage:

::

   sample-async [-s server_address] [-t RR_type] input_file

Options and arguments:

``-s server_address``
   This is the IPv4 address of the recursive server to which queries are sent.
   (IPv6 addresses are not supported in this implementation.)

``-t RR_type``
   This specifies the RR type of the queries. The default is the A RR.

``input_file``
   This is a list of domain names to be resolved; each line consists of a single
   domain name. For example:

   ::

            www.example.com
            mx.example.net
            ns.xxx.example

``sample-request``: a Simple DNS Transaction Client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This application sends a query to a specified server, and prints the response with
minimal processing. It does not act as a stub resolver; it stops the
processing once it receives any response from the server, whether it be a
referral or an alias (CNAME or DNAME) that requires further queries
to get the ultimate answer. In other words, this utility acts as a very
simplified ``dig``.

Usage:

::

   sample-request [-t RRtype] server_address hostname

Options and arguments:

``-t RRtype``
   This specifies the RR type of the queries. The default is the A RR.

``server_address``
   This is the IP(v4/v6) address of the recursive server to which the query is
   sent.

``hostname``
   This indicates the domain name for the query.

``sample-gai``: ``getaddrinfo()`` and ``getnameinfo()`` Test Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a test program to check ``getaddrinfo()`` and ``getnameinfo()``
behavior. It takes a host name as an argument, calls ``getaddrinfo()``
with the given host name, and calls ``getnameinfo()`` with the resulting
IP addresses returned by ``getaddrinfo()``. If the ``dns.conf`` file exists
and defines a trust anchor, the underlying resolver acts as a
validating resolver; ``getaddrinfo()``/``getnameinfo()`` fails
with an EAI_INSECUREDATA error when DNSSEC validation fails.

Usage:

::

   sample-gai hostname

``sample-update``: a Simple Dynamic Update Client Program
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This application accepts a single update command as a command-line argument, sends an
update request message to the authoritative server, and shows the
response from the server. In other words, this is a simplified
``nsupdate``.

Usage:

::

   sample-update [options] (add|delete) "update data"

Options and arguments:

``-a auth_server``
   This is the IP address of the authoritative server that has authority for the
   zone containing the update name. This should normally be the primary
   authoritative server that accepts dynamic updates. It can also be a
   secondary server that is configured to forward update requests to the
   primary server.

``-k keyfile``
   This is a TSIG keyfile to secure the update transaction. The keyfile format
   is the same as that for the ``nsupdate`` utility.

``-p prerequisite``
   This is a prerequisite for the update; only one prerequisite can be
   specified. The prerequisite format is the same as that accepted
   by the ``nsupdate`` utility.

``-r recursive_server``
   This is the IP address of a recursive server used by this utility. A
   recursive server may be necessary to identify the authoritative
   server address to which the update request is sent.

``-z zonename``
   This is the domain name of the zone that contains the authoritative zone for the update name.

``(add|delete)``
   This specifies the type of update operation. Either "add" or "delete" must
   be specified.

``update data``
   This specifies the data to be updated. A typical example of the data
   looks like ``name TTL RRtype RDATA``.

.. note::

   In practice, either ``-a`` or ``-r`` must be specified. Other arguments are
   optional; the underlying library routine tries to identify the
   appropriate server and the zone name for the update.

Here's an example. Assuming the primary authoritative server of the
dynamic.example.com zone has an IPv6 address 2001:db8::1234:

::

   $ sample-update -a sample-update -k Kxxx.+nnn+mmmm.key add "foo.dynamic.example.com 30 IN A 192.168.2.1"

adds an A RR for ``foo.dynamic.example.com`` using the given key.

::

   $ sample-update -a sample-update -k Kxxx.+nnn+mmmm.key delete "foo.dynamic.example.com 30 IN A"

removes all A RRs for ``foo.dynamic.example.com`` using the given key.

::

   $ sample-update -a sample-update -k Kxxx.+nnn+mmmm.key delete "foo.dynamic.example.com"

removes all RRs for ``foo.dynamic.example.com`` using the given key.

``nsprobe``: Domain/Name Server Checker Under RFC 4074
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This application checks a set of domains to verify that the name servers of the domains behave
correctly according to :rfc:`4074`. This is included in the set of sample
programs to show how the export library can be used in a DNS-related
application.

Usage:

::

   nsprobe [-d] [-v [-v...]] [-c cache_address] [input_file]

Options and arguments:

``-d``
   This instructs the command to run in "debug" mode. With this option, ``nsprobe`` dumps every RRs it
   receives.

``-v``
   This increases the verbosity of other normal log messages. This can be
   specified multiple times.

``-c cache_address``
   This specifies the IP address of a recursive (caching) name server. ``nsprobe``
   uses this server to get the NS RRset of each domain and the A and/or
   AAAA RRsets for the name servers. The default value is 127.0.0.1.

``input_file``
   This is the name of a file containing a list of domain (zone) names to be probed.
   When omitted, the standard input is used. Each line of the input
   file specifies a single domain name, such as ``example.com``. In general,
   this domain name must be the apex name of a DNS zone (unlike
   normal host names such as ``www.example.com``). ``nsprobe`` first
   identifies the NS RRsets for the given domain name and sends A and
   AAAA queries to these servers for some widely used names under the
   zone; specifically, it adds "www" and "ftp" to the zone name.

Library References
------------------

There is currently no formal "manual" for the libraries
other than this document, the header files (some of which provide fairly
detailed explanations), and some sample application programs.
