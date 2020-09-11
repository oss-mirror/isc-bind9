include $(top_srcdir)/Makefile.top

lib_LTLIBRARIES = libdns.la

nodist_libdns_ladir = $(includedir)/dns
nodist_libdns_la_HEADERS =		\
	include/dns/enumclass.h		\
	include/dns/enumtype.h		\
	include/dns/rdatastruct.h

nodist_libdns_la_SOURCES =		\
	$(nodist_libdns_la_HEADERS)	\
	code.h

BUILT_SOURCES =				\
	$(nodist_libdns_la_SOURCES)

CLEANFILES =				\
	$(nodist_libdns_la_SOURCES)	\
	gen$(BUILD_EXEEXT)

gen$(BUILD_EXEEXT): gen.c gen.h
	$(CC_FOR_BUILD) -g -I. $(GEN_NEED_OPTARG) $(srcdir)/gen.c -o $@

EXTRA_DIST =				\
	dnstap.proto			\
	gen.c				\
	gen.h				\
	rdata/rdatastructsuf.h		\
	rdata/generic			\
	rdata/generic/ns_2.c		\
	rdata/generic/mg_8.h		\
	rdata/generic/zonemd_63.h	\
	rdata/generic/isdn_20.c		\
	rdata/generic/md_3.c		\
	rdata/generic/isdn_20.h		\
	rdata/generic/tlsa_52.c		\
	rdata/generic/eui64_109.c	\
	rdata/generic/tkey_249.c	\
	rdata/generic/txt_16.h		\
	rdata/generic/mg_8.c		\
	rdata/generic/l32_105.c		\
	rdata/generic/rrsig_46.c	\
	rdata/generic/naptr_35.c	\
	rdata/generic/sig_24.c		\
	rdata/generic/loc_29.c		\
	rdata/generic/dlv_32769.c	\
	rdata/generic/rkey_57.h		\
	rdata/generic/tlsa_52.h		\
	rdata/generic/ta_32768.h	\
	rdata/generic/csync_62.c	\
	rdata/generic/keydata_65533.h	\
	rdata/generic/ptr_12.c		\
	rdata/generic/rrsig_46.h	\
	rdata/generic/dname_39.c	\
	rdata/generic/openpgpkey_61.h	\
	rdata/generic/rp_17.h		\
	rdata/generic/nsec_47.c		\
	rdata/generic/ds_43.c		\
	rdata/generic/uri_256.c		\
	rdata/generic/l32_105.h		\
	rdata/generic/nsec3_50.c	\
	rdata/generic/talink_58.h	\
	rdata/generic/ninfo_56.h	\
	rdata/generic/ipseckey_45.h	\
	rdata/generic/nid_104.h		\
	rdata/generic/x25_19.c		\
	rdata/generic/eui48_108.h	\
	rdata/generic/ds_43.h		\
	rdata/generic/avc_258.c		\
	rdata/generic/rp_17.c		\
	rdata/generic/mx_15.h		\
	rdata/generic/afsdb_18.c	\
	rdata/generic/hinfo_13.h	\
	rdata/generic/mb_7.h		\
	rdata/generic/naptr_35.h	\
	rdata/generic/spf_99.c		\
	rdata/generic/mr_9.h		\
	rdata/generic/key_25.h		\
	rdata/generic/txt_16.c		\
	rdata/generic/smimea_53.c	\
	rdata/generic/cds_59.h		\
	rdata/generic/eui64_109.h	\
	rdata/generic/mf_4.h		\
	rdata/generic/sink_40.h		\
	rdata/generic/minfo_14.c	\
	rdata/generic/cname_5.h		\
	rdata/generic/cdnskey_60.h	\
	rdata/generic/doa_259.h		\
	rdata/generic/null_10.c		\
	rdata/generic/opt_41.c		\
	rdata/generic/openpgpkey_61.c	\
	rdata/generic/nid_104.c		\
	rdata/generic/nsec3_50.h	\
	rdata/generic/sink_40.c		\
	rdata/generic/cds_59.c		\
	rdata/generic/nsec_47.h		\
	rdata/generic/ninfo_56.c	\
	rdata/generic/gpos_27.c		\
	rdata/generic/smimea_53.h	\
	rdata/generic/ptr_12.h		\
	rdata/generic/talink_58.c	\
	rdata/generic/dnskey_48.c	\
	rdata/generic/hinfo_13.c	\
	rdata/generic/lp_107.c		\
	rdata/generic/sshfp_44.h	\
	rdata/generic/proforma.c	\
	rdata/generic/loc_29.h		\
	rdata/generic/nxt_30.h		\
	rdata/generic/proforma.h	\
	rdata/generic/lp_107.h		\
	rdata/generic/opt_41.h		\
	rdata/generic/doa_259.c		\
	rdata/generic/amtrelay_260.c	\
	rdata/generic/eui48_108.c	\
	rdata/generic/mr_9.c		\
	rdata/generic/hip_55.h		\
	rdata/generic/hip_55.c		\
	rdata/generic/caa_257.h		\
	rdata/generic/avc_258.h		\
	rdata/generic/amtrelay_260.h	\
	rdata/generic/cert_37.h		\
	rdata/generic/caa_257.c		\
	rdata/generic/dnskey_48.h	\
	rdata/generic/zonemd_63.c	\
	rdata/generic/keydata_65533.c	\
	rdata/generic/rt_21.c		\
	rdata/generic/nxt_30.c		\
	rdata/generic/minfo_14.h	\
	rdata/generic/l64_106.h		\
	rdata/generic/nsec3param_51.h	\
	rdata/generic/soa_6.c		\
	rdata/generic/cert_37.c		\
	rdata/generic/sig_24.h		\
	rdata/generic/dname_39.h	\
	rdata/generic/ta_32768.c	\
	rdata/generic/tkey_249.h	\
	rdata/generic/md_3.h		\
	rdata/generic/l64_106.c		\
	rdata/generic/mx_15.c		\
	rdata/generic/dlv_32769.h	\
	rdata/generic/soa_6.h		\
	rdata/generic/ipseckey_45.c	\
	rdata/generic/cname_5.c		\
	rdata/generic/key_25.c		\
	rdata/generic/uri_256.h		\
	rdata/generic/nsec3param_51.c	\
	rdata/generic/gpos_27.h		\
	rdata/generic/rkey_57.c		\
	rdata/generic/ns_2.h		\
	rdata/generic/sshfp_44.c	\
	rdata/generic/null_10.h		\
	rdata/generic/spf_99.h		\
	rdata/generic/x25_19.h		\
	rdata/generic/rt_21.h		\
	rdata/generic/mf_4.c		\
	rdata/generic/mb_7.c		\
	rdata/generic/afsdb_18.h	\
	rdata/generic/csync_62.h	\
	rdata/generic/cdnskey_60.c	\
	rdata/hs_4			\
	rdata/hs_4/a_1.h		\
	rdata/hs_4/a_1.c		\
	rdata/ch_3			\
	rdata/ch_3/a_1.h		\
	rdata/ch_3/a_1.c		\
	rdata/in_1			\
	rdata/in_1/apl_42.c		\
	rdata/in_1/aaaa_28.h		\
	rdata/in_1/nsap-ptr_23.h	\
	rdata/in_1/apl_42.h		\
	rdata/in_1/atma_34.h		\
	rdata/in_1/a6_38.h		\
	rdata/in_1/srv_33.h		\
	rdata/in_1/nsap-ptr_23.c	\
	rdata/in_1/aaaa_28.c		\
	rdata/in_1/wks_11.c		\
	rdata/in_1/nimloc_32.c		\
	rdata/in_1/dhcid_49.h		\
	rdata/in_1/px_26.c		\
	rdata/in_1/wks_11.h		\
	rdata/in_1/eid_31.h		\
	rdata/in_1/atma_34.c		\
	rdata/in_1/eid_31.c		\
	rdata/in_1/nimloc_32.h		\
	rdata/in_1/nsap_22.h		\
	rdata/in_1/dhcid_49.c		\
	rdata/in_1/a6_38.c		\
	rdata/in_1/kx_36.c		\
	rdata/in_1/a_1.h		\
	rdata/in_1/a_1.c		\
	rdata/in_1/srv_33.c		\
	rdata/in_1/kx_36.h		\
	rdata/in_1/px_26.h		\
	rdata/in_1/nsap_22.c		\
	rdata/any_255			\
	rdata/any_255/tsig_250.h	\
	rdata/any_255/tsig_250.c	\
	rdata/rdatastructpre.h

include/dns/enumtype.h: gen Makefile
	mkdir -p include/dns
	$(builddir)/gen -s $(srcdir) -t > $@

include/dns/enumclass.h: gen Makefile
	mkdir -p include/dns
	$(builddir)/gen -s $(srcdir) -c > $@

include/dns/rdatastruct.h: gen rdata/rdatastructpre.h rdata/rdatastructsuf.h Makefile
	mkdir -p include/dns
	$(builddir)/gen -s $(srcdir) -i \
		-P $(srcdir)/rdata/rdatastructpre.h \
		-S $(srcdir)/rdata/rdatastructsuf.h > $@

code.h: gen Makefile
	$(builddir)/gen -s $(srcdir) > $@

libdns_ladir = $(includedir)/dns
libdns_la_HEADERS =			\
	include/dns/acl.h		\
	include/dns/adb.h		\
	include/dns/badcache.h		\
	include/dns/bit.h		\
	include/dns/byaddr.h		\
	include/dns/cache.h		\
	include/dns/callbacks.h		\
	include/dns/catz.h		\
	include/dns/cert.h		\
	include/dns/client.h		\
	include/dns/clientinfo.h	\
	include/dns/compress.h		\
	include/dns/db.h		\
	include/dns/dbiterator.h	\
	include/dns/diff.h		\
	include/dns/dispatch.h		\
	include/dns/dlz.h		\
	include/dns/dlz_dlopen.h	\
	include/dns/dns64.h		\
	include/dns/dnsrps.h		\
	include/dns/dnssec.h		\
	include/dns/ds.h		\
	include/dns/dsdigest.h		\
	include/dns/dnstap.h		\
	include/dns/dyndb.h		\
	include/dns/ecs.h		\
	include/dns/edns.h		\
	include/dns/events.h		\
	include/dns/fixedname.h		\
	include/dns/forward.h		\
	include/dns/geoip.h		\
	include/dns/ipkeylist.h		\
	include/dns/iptable.h		\
	include/dns/journal.h		\
	include/dns/kasp.h		\
	include/dns/keydata.h		\
	include/dns/keyflags.h		\
	include/dns/keymgr.h		\
	include/dns/keytable.h		\
	include/dns/keyvalues.h		\
	include/dns/lib.h		\
	include/dns/librpz.h		\
	include/dns/lookup.h		\
	include/dns/log.h		\
	include/dns/master.h		\
	include/dns/masterdump.h	\
	include/dns/message.h		\
	include/dns/name.h		\
	include/dns/ncache.h		\
	include/dns/nsec.h		\
	include/dns/nsec3.h		\
	include/dns/nta.h		\
	include/dns/opcode.h		\
	include/dns/order.h		\
	include/dns/peer.h		\
	include/dns/private.h		\
	include/dns/rbt.h		\
	include/dns/rcode.h		\
	include/dns/rdata.h		\
	include/dns/rdataclass.h	\
	include/dns/rdatalist.h		\
	include/dns/rdataset.h		\
	include/dns/rdatasetiter.h	\
	include/dns/rdataslab.h		\
	include/dns/rdatatype.h		\
	include/dns/request.h		\
	include/dns/resolver.h		\
	include/dns/result.h		\
	include/dns/rootns.h		\
	include/dns/rpz.h		\
	include/dns/rriterator.h	\
	include/dns/rrl.h		\
	include/dns/sdb.h		\
	include/dns/sdlz.h		\
	include/dns/secalg.h		\
	include/dns/secproto.h		\
	include/dns/soa.h		\
	include/dns/ssu.h		\
	include/dns/stats.h		\
	include/dns/tcpmsg.h		\
	include/dns/time.h		\
	include/dns/timer.h		\
	include/dns/transport.h		\
	include/dns/tkey.h		\
	include/dns/tsec.h		\
	include/dns/tsig.h		\
	include/dns/ttl.h		\
	include/dns/types.h		\
	include/dns/update.h		\
	include/dns/validator.h		\
	include/dns/view.h		\
	include/dns/xfrin.h		\
	include/dns/zone.h		\
	include/dns/zonekey.h		\
	include/dns/zoneverify.h	\
	include/dns/zt.h

dstdir = $(includedir)/dst
dst_HEADERS =				\
	include/dst/dst.h		\
	include/dst/gssapi.h		\
	include/dst/result.h

libdns_la_SOURCES =			\
	$(libdns_la_HEADERS)		\
	$(dst_HEADERS)			\
	acl.c				\
	adb.c				\
	badcache.c			\
	byaddr.c			\
	cache.c				\
	callbacks.c			\
	catz.c				\
	clientinfo.c			\
	compress.c			\
	db.c				\
	dbiterator.c			\
	diff.c				\
	dispatch.c			\
	dlz.c				\
	dns64.c				\
	dnsrps.c			\
	dnssec.c			\
	ds.c				\
	dst_api.c			\
	dst_internal.h			\
	dst_openssl.h			\
	dst_parse.c			\
	dst_parse.h			\
	dst_pkcs11.h			\
	dst_result.c			\
	dyndb.c				\
	ecs.c				\
	fixedname.c			\
	forward.c			\
	gssapictx.c			\
	hmac_link.c			\
	ipkeylist.c			\
	iptable.c			\
	journal.c			\
	kasp.c				\
	key.c				\
	keydata.c			\
	keymgr.c			\
	keytable.c			\
	lib.c				\
	log.c				\
	lookup.c			\
	master.c			\
	masterdump.c			\
	message.c			\
	name.c				\
	ncache.c			\
	nsec.c				\
	nsec3.c				\
	nta.c				\
	openssl_link.c			\
	openssldh_link.c		\
	order.c				\
	peer.c				\
	private.c			\
	rbt.c				\
	rbtdb.h				\
	rbtdb.c				\
	rcode.c				\
	rdata.c				\
	rdatalist.c			\
	rdataset.c			\
	rdatasetiter.c			\
	rdataslab.c			\
	request.c			\
	resolver.c			\
	result.c			\
	rootns.c			\
	rpz.c				\
	rrl.c				\
	rriterator.c			\
	sdb.c				\
	sdlz.c				\
	soa.c				\
	ssu.c				\
	ssu_external.c			\
	stats.c				\
	tcpmsg.c			\
	time.c				\
	timer.c				\
	transport.c			\
	tkey.c				\
	tsec.c				\
	tsig.c				\
	ttl.c				\
	update.c			\
	validator.c			\
	view.c				\
	xfrin.c				\
	zone.c				\
	zoneverify.c			\
	zonekey.c			\
	zt.c				\
	client.c			\
	rdatalist_p.h			\
	tsig_p.h			\
	zone_p.h

if HAVE_GSSAPI
libdns_la_SOURCES +=			\
	gssapi_link.c
endif

if HAVE_PKCS11
libdns_la_SOURCES +=		\
	pkcs11.c		\
	pkcs11ecdsa_link.c	\
	pkcs11eddsa_link.c	\
	pkcs11rsa_link.c
else !HAVE_PKCS11
libdns_la_SOURCES +=		\
	opensslecdsa_link.c	\
	openssleddsa_link.c	\
	opensslrsa_link.c
endif

if HAVE_GEOIP2
libdns_la_SOURCES += \
	geoip2.c
endif

libdns_la_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)	\
	$(LIBISC_CFLAGS)	\
	$(LIBUV_CFLAGS)		\
	$(OPENSSL_CFLAGS)

libdns_la_LDFLAGS =		\
	$(AM_LDFLAGS)		\
	-release "$(PACKAGE_VERSION)"

libdns_la_LIBADD =		\
	$(LIBISC_LIBS)		\
	$(LIBUV_LIBS)		\
	$(OPENSSL_LIBS)

if HAVE_JSON_C
libdns_la_CPPFLAGS +=		\
	$(JSON_C_CFLAGS)

libdns_la_LIBADD +=		\
	$(JSON_C_LIBS)
endif HAVE_JSON_C

if HAVE_LIBXML2
libdns_la_CPPFLAGS +=		\
	$(LIBXML2_CFLAGS)

libdns_la_LIBADD +=		\
	$(LIBXML2_LIBS)
endif HAVE_LIBXML2

if HAVE_GSSAPI
libdns_la_CPPFLAGS +=		\
	$(GSSAPI_CFLAGS)	\
	$(KRB5_CFLAGS)
libdns_la_LIBADD +=		\
	$(GSSAPI_LIBS)		\
	$(KRB5_LIBS)
endif

if HAVE_GEOIP2
libdns_la_CPPFLAGS +=		\
	$(MAXMINDDB_CFLAGS)
libdns_la_LDFLAGS +=		\
	$(MAXMINDDB_LIBS)
endif

if HAVE_DNSTAP
nodist_libdns_la_SOURCES +=	\
	dnstap.pb-c.h		\
	dnstap.pb-c.c

libdns_la_SOURCES +=		\
	dnstap.c

dnstap.pb-c.h dnstap.pb-c.c: dnstap.proto
	$(PROTOC_C) --proto_path=$(srcdir) --c_out=. dnstap.proto

libdns_la_CPPFLAGS += $(DNSTAP_CFLAGS)
libdns_la_LIBADD += $(DNSTAP_LIBS)
endif

if HAVE_LMDB
libdns_la_CPPFLAGS += $(LMDB_CFLAGS)
libdns_la_LIBADD += $(LMDB_LIBS)
endif

if HAVE_CMOCKA
SUBDIRS = tests
endif
