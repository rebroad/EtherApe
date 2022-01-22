## Process this file with automake to produce Makefile.in

SUBDIRS = src doc glade m4 po

# standard props
DATADIR=.

DISTCHECK_CONFIGURE_FLAGS=

indent:
	cd src && make indent

man_MANS = etherape.1

confdir = $(sysconfdir)/etherape
conf_DATA =


Developmentdir = $(datadir)/applications
Development_DATA = etherape.desktop

pixmapsdir = $(datadir)/pixmaps
pixmaps_DATA = etherape.png

purge:
	rm -f *~ *.bak *.tar.gz
	cd src && make purge

splint:
	cd src && make splint

DISTCLEANFILES=

EXTRA_DIST = config.rpath mkinstalldirs  \
	README.bugs		\
	FAQ			\
	ChangeLog		\
	etherape.spec		\
	etherape.spec.in	\
	etherape.desktop.in	\
	PKGBUILD		\
	PKGBUILD.in		\
	src/glade-strings	\
	$(Development_DATA)	\
	$(pixmaps_DATA)		\
	$(man_MANS)		\
	m4			\
	$(conf_DATA)


dist-hook: etherape.spec
	cp etherape.spec $(distdir)

ACLOCAL_AMFLAGS = -I m4
