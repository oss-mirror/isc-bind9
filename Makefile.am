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
