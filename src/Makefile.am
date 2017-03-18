## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = subdir-objects

confdir = $(sysconfdir)/etherape
gladedir   = $(datadir)/etherape/glade

etherape_CPPFLAGS  = \
	-I$(top_srcdir)/intl \
	-DGLADEDIR=\""$(gladedir)"\" \
	-DCONFDIR=\""$(confdir)"\" \
	$(WARN_CFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(ETHERAPE_CFLAGS) 

bin_PROGRAMS = etherape

## name resolution sources 
etherape_names_SOURCES = \
	names/eth_resolv.c names/eth_resolv.h \
	names/dns.c names/dns.h \
	names/ip-cache.c names/ip-cache.h \
	names/names.c names/names.h \
	names/names_netbios.c names/names_netbios.h

# statistics sources
etherape_stats_SOURCES = \
	stats/basic_stats.c stats/basic_stats.h \
	stats/conversations.c stats/conversations.h \
	stats/decode_proto.c stats/decode_proto.h \
	stats/links.c stats/links.h \
	stats/node.c stats/node.h \
	stats/node_id.c stats/node_id.h \
	stats/protocols.c stats/protocols.h \
	stats/prot_types.h stats/pkt_info.h \
	stats/traffic_stats.c stats/traffic_stats.h \
	stats/util.c stats/util.h

# capture sources
etherape_capture_SOURCES = \
	capture/capture.c capture/capture.h \
	capture/capctl.c capture/capctl.h \
	capture/cap-util.c capture/cap-util.h \
	capture/capctl-msg.h

etherape_SOURCES = \
	$(etherape_stats_SOURCES) \
	$(etherape_names_SOURCES) \
	$(etherape_capture_SOURCES) \
	main.c main.h \
	common.h \
	appdata.c appdata.h\
	callbacks.c callbacks.h \
	compat.c compat.h \
	datastructs.c datastructs.h \
	diagram.c diagram.h \
	export.c export.h \
	info_windows.c info_windows.h \
	menus.c menus.h \
	node_windows.c node_windows.h \
	pref_dialog.c pref_dialog.h \
	preferences.c preferences.h \
	ui_utils.c ui_utils.h

if !HAVE_LIBCARES
etherape_SOURCES += names/thread_resolve.c names/thread_resolve.h
endif

etherape_LDADD = $(ETHERAPE_LIBS) $(PCAP_LIBS) $(PTHREAD_LIBS) $(PTHREAD_CFLAGS)
etherape_LDFLAGS = $(ETHERAPE_LDFLAGS) 

.indent: $(etherape_SOURCES) $(etherape_INCLUDES)
	indent $? 
	touch .indent
indent: .indent 

purge:
	rm -f *~ *.bak

splint:
	splint -I.. +posixlib +gnuextensions +charintliteral -nullassign $(etherape_CPPFLAGS) $(etherape_SOURCES)
