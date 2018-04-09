#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT([etherape],[0.9.18])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall foreign])

# defines
AC_DEFINE([HAVE_CATGETS],[],[cmt])
AC_DEFINE([GETTEXT_PACKAGE],[],[cmt])
AC_DEFINE([HAVE_LIBSM],[],[cmt])
AC_DEFINE([HAVE_LIBPCAP],[],[cmt])
AC_DEFINE([HAVE_U_INT],[],[cmt])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
#AC_PROG_INTLTOOL(0.27)

# Checks for libraries.
PKG_CHECK_MODULES(ETHERAPE, glib-2.0 libglade-2.0 libgnomecanvas-2.0)
AC_SUBST(ETHERAPE_CFLAGS)
AC_SUBST(ETHERAPE_LDFLAGS)
AC_SUBST(ETHERAPE_LIBS)
AX_PTHREAD

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h sys/wait.h unistd.h math.h])

AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([net/if.h], [], [],
 [#include <stdio.h>
  #if STDC_HEADERS
  # include <stdlib.h>
  # include <stddef.h>
  #else
  # if HAVE_STDLIB_H
  # include <stdlib.h>
  # endif
  #endif
  #if HAVE_SYS_SOCKET_H
  # include <sys/socket.h>
  #endif
])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

AC_ARG_ENABLE([warnings],
  AS_HELP_STRING([--disable-warnings], [Disable compiler warnings @<:@default=enabled@:>@]))

if test "$enable_warnings" != no; then
  ETHERAPE_CFLAGS="$ETHERAPE_CFLAGS -Wall"
fi

AC_ARG_ENABLE([werror],
  AS_HELP_STRING([--enable-werror], [Treat warnings as errors @<:@default=disabled@:>@]))

if test "$enable_werror" = yes; then
  ETHERAPE_CFLAGS="$ETHERAPE_CFLAGS -Werror"
fi

AC_ARG_ENABLE([asan],
  AS_HELP_STRING([--enable-asan],
    [Compile with GCC/Clang's address sanitizer (incompatible with --enable-tsan) @<:@default=disabled@:>@]))

if test "$enable_asan" = yes; then
  ETHERAPE_CFLAGS="$ETHERAPE_CFLAGS -fsanitize=address"
  ETHERAPE_LDFLAGS="$ETHERAPE_LDFLAGS -fsanitize=address"
fi

AC_ARG_ENABLE([ubsan],
  AS_HELP_STRING([--enable-ubsan], [Compile with GCC/Clang's undefined-behavior sanitizer @<:@default=disabled@:>@]))

if test "$enable_ubsan" = yes; then
  ETHERAPE_CFLAGS="$ETHERAPE_CFLAGS -fsanitize=undefined"
  ETHERAPE_LDFLAGS="$ETHERAPE_LDFLAGS -fsanitize=undefined"
fi

AC_ARG_ENABLE([tsan],
  AS_HELP_STRING([--enable-tsan],
    [Compile with GCC/Clang's thread sanitizer (incompatible with --enable-asan) @<:@default=disabled@:>@]))

if test "$enable_tsan" = yes; then
  if test "$enable_asan" = yes; then
    AC_MSG_ERROR([--enable-tsan and --enable-asan are mutually incompatible])
  fi
  ETHERAPE_CFLAGS="$ETHERAPE_CFLAGS -fsanitize=thread"
  ETHERAPE_LDFLAGS="$ETHERAPE_LDFLAGS -fsanitize=thread"
fi

# checks for osx or disable-gdk-input-add
AC_ARG_ENABLE(gdk-input-add,
  [AC_HELP_STRING([--disable-gdk-input-add],[Use timers for live capture instead of gdk_input_add.])],
  [use_gdk_input_add=$enableval], [use_gdk_input_add=yes])

AC_COMPILE_IFELSE([AC_LANG_SOURCE([[int main(int argc, char *argv[]){return __APPLE__ + __MACH__;}]])],
  use_gdk_input_add=no)

if test $use_gdk_input_add = no; then
  AC_DEFINE([DISABLE_GDKINPUTADD], [1], [disables gdk_input_add])
  AC_MSG_NOTICE([gtk_input_add disabled])
fi

AC_CHECK_FUNC(getnameinfo, [has_getnameinfo=yes],
  AC_CHECK_LIB(bind, getnameinfo, [has_getnameinfo=yes],
   AC_CHECK_LIB(resolv, getnameinfo, [has_getnameinfo=yes],
    AC_CHECK_LIB(nsl, getnameinfo, [has_getnameinfo=yes],[has_getnameinfo=no]))))

if test $has_getnameinfo = no; then
 AC_MSG_NOTICE([getnameinfo not found, trying with gethostbyaddr])
 AC_CHECK_FUNC(gethostbyaddr, [has_gethostbyaddr=yes],
  AC_CHECK_LIB(bind, gethostbyaddr, [has_gethostbyaddr=yes],
   AC_CHECK_LIB(resolv, gethostbyaddr, [has_gethostbyaddr=yes],
     AC_CHECK_LIB(nsl, gethostbyaddr, [has_gethostbyaddr=yes],
      [AC_MSG_ERROR([Missing both getnameinfo and gethostbyaddr. Please install a resolver library.])]
      ))))

 if test $has_gethostbyaddr = yes; then
   AC_MSG_WARN([Found only gethostbyaddr, while getnameinfo does not exists, resolving is restricted to single thread.])
   AC_DEFINE([FORCE_SINGLE_THREAD], [1], [found only gethostbyaddr, while getnameinfo does not exists, resolving is restricted to single thread.])
 fi
fi

# Handle --with-c-ares
AC_ARG_WITH([c-ares],
  AS_HELP_STRING([--with-c-ares], [use the c-ares library for DNS resolution @<:@default=no@:>@]),
  [],
  [with_c_ares=no])

if test $with_c_ares = yes; then
  AC_SEARCH_LIBS([ares_init], [cares],
    [AC_DEFINE([HAVE_LIBCARES], [1], [Define to 1 to use the c-ares DNS library])],
    [AC_MSG_FAILURE([--with-c-ares was given, but the c-ares library was not found])])
fi
AM_CONDITIONAL([HAVE_LIBCARES], [test $with_c_ares = yes])

# Check for the pcap library.
AC_ARG_ENABLE(static-pcap,
  [  --enable-static-pcap    Used to build the rpm within Debian. ],
  STATIC_PCAP=yes)
AC_ETHEREAL_PCAP_CHECK

# check for other libraries (needed for AC_CHECK_FUNCS)
AC_SEARCH_LIBS(pow, [m])
AC_SEARCH_LIBS(glib_check_version, [glib-2.0])
AC_SEARCH_LIBS(poptGetContext, [popt])

# Check for inet_ntop (it's supposed to exists everywhere, but ...)
AC_CHECK_FUNCS([inet_ntop])

# check for g_list_free_full (glib < 2.28)
AC_CHECK_FUNCS([g_list_free_full])

# check for g_ptr_array_insert (glib < 2.40, RHEL7/CENTOS7 and before)
AC_CHECK_FUNCS([g_ptr_array_insert])

dnl Add the languages which your application supports here.
ALL_LINGUAS="es fr nl tr sv it de"
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.11.5])
GETTEXT_PACKAGE=etherape
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE")

dnl Set PACKAGE_LOCALE_DIR in config.h.
if test "x${prefix}" = "xNONE"; then
  AC_DEFINE_UNQUOTED(PACKAGE_LOCALE_DIR, "${ac_default_prefix}/share/locale",[package locale directory])
else
  AC_DEFINE_UNQUOTED(PACKAGE_LOCALE_DIR, "${prefix}/share/locale",[package locale directory])
fi

dnl Set PIXMAPS_DIR in config.h.
if test "x${prefix}" = "xNONE"; then
  AC_DEFINE_UNQUOTED(PIXMAPS_DIR, "${ac_default_prefix}/share/pixmaps",[pixmaps directory])
else
  AC_DEFINE_UNQUOTED(PIXMAPS_DIR, "${prefix}/share/pixmaps",[pixmaps directory])
fi

dnl initialize yelp doc macros
YELP_HELP_INIT

dnl get mercurial version - sadly, this works only on a developer repo ...
dnl AC_CONFIG_COMMANDS_PRE([
dnl hg_id=`hg identify -i`
dnl AC_DEFINE_UNQUOTED(PACKAGE_SCM_REV, ["${hg_id}"], [mercurial revision])
dnl AC_MSG_NOTICE([mercurial id: ${hg_id}])
dnl ])

dnl check for endianess (need it for Per Packet Incapsulation)
AC_C_BIGENDIAN

dnl see if the linker allows "--export-dynamic"
AC_MSG_CHECKING([if the linker allows -Wl,--export-dynamic])
tmp_LDFLAGS=$LDFLAGS
LDFLAGS="$LDFLAGS -Wl,--export-dynamic"
AC_LINK_IFELSE([AC_LANG_SOURCE([int main(int argc, char *argv[]){return 0;}])],
  AC_MSG_RESULT([yes]),
  AC_MSG_RESULT([no])
  LDFLAGS=$tmp_LDFLAGS)

AC_CONFIG_FILES([Makefile
	   po/Makefile.in
           etherape.spec
           etherape.desktop
           PKGBUILD
           glade/Makefile
           src/Makefile
	   m4/Makefile
           doc/Makefile])
AC_OUTPUT
