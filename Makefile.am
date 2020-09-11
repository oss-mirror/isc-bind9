include $(top_srcdir)/Makefile.top

SUBDIRS = . lib doc bin fuzz

BUILT_SOURCES = bind.keys.h
CLEANFILES = bind.keys.h

bind.keys.h: bind.keys Makefile
	${PERL} ${top_srcdir}/util/bindkeys.pl ${top_srcdir}/bind.keys > $@

dist_sysconf_DATA = bind.keys

.PHONY: doc

EXTRA_DIST = 			\
	util/bindkeys.pl	\
	contrib			\
	CHANGES			\
	COPYRIGHT		\
	LICENSE			\
	CODE_OF_CONDUCT.md	\
	CONTRIBUTING.md		\
	HISTORY.md		\
	OPTIONS.md		\
	PLATFORMS.md		\
	README.md

dist-hook:
	find $(distdir) -type f -name .gitignore -delete
	git rev-parse --short HEAD | cut -b1-7 > $(distdir)/srcid

# By default 'dist' creates read-only directories and files. As system test
# needs write access to some of those, we add necessary permissions here.
distcheck-hook:
	find $(distdir)/bin/tests/system -exec chmod u+w {} \;
	chmod u+w $(distdir)/lib/isc/tests/testdata/file/
	chmod u+w $(distdir)/lib/dns/tests/
	chmod u+w $(distdir)/lib/dns/tests/testdata/zt/zone1.db
