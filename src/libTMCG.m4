dnl Autoconf macros for libTMCG (source adapted from libgcrypt.m4)
dnl       Copyright (C) 2002, 2004  Free Software Foundation, Inc.
dnl                     2005  Heiko Stamer <stamer@gaos.org>
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


dnl AM_PATH_LIBTMCG([MINIMUM-VERSION,
dnl                 [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libTMCG and define LIBTMCG_CFLAGS and LIBTMCG_LIBS.
dnl MINIMUN-VERSION is a string with the version number optionalliy prefixed
dnl with the API version to also check the API compatibility. Example:
dnl a MINIMUN-VERSION of 1:1.2.5 won't pass the test unless the installed
dnl version of libTMCG is at least 1.2.5 *and* the API number is 1. Using
dnl this features allows to prevent build against newer versions of libTMCG
dnl with a changed API.
dnl
AC_DEFUN([AM_PATH_LIBTMCG],
[ AC_ARG_WITH(libTMCG-prefix,
            AC_HELP_STRING([--with-libTMCG-prefix=PFX],
                           [prefix where libTMCG is installed (optional)]),
     libtmcg_config_prefix="$withval", libtmcg_config_prefix="")
  if test x$libtmcg_config_prefix != x ; then
     if test x${LIBTMCG_CONFIG+set} != xset ; then
        LIBTMCG_CONFIG=$libtmcg_config_prefix/bin/libTMCG-config
     fi
  fi

  AC_PATH_PROG(LIBTMCG_CONFIG, libTMCG-config, no)
  tmp=ifelse([$1], ,1:1.0.0,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
     req_libtmcg_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
     min_libtmcg_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
     req_libtmcg_api=0
     min_libtmcg_version="$tmp"
  fi

  AC_MSG_CHECKING(for libTMCG version >= $min_libtmcg_version)
  ok=no
  if test "$LIBTMCG_CONFIG" != "no" ; then
    req_major=`echo $min_libtmcg_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libtmcg_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libtmcg_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    libtmcg_config_version=`$LIBTMCG_CONFIG --version`
    major=`echo $libtmcg_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $libtmcg_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $libtmcg_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
    if test "$major" -gt "$req_major"; then
        ok=yes
    else 
        if test "$major" -eq "$req_major"; then
            if test "$minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$minor" -eq "$req_minor"; then
                   if test "$micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
  fi
  if test $ok = yes; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
  if test $ok = yes; then
     # If we have a recent libTMCG, we should also check that the
     # API is compatible
     if test "$req_libtmcg_api" -gt 0 ; then
        tmp=`$LIBTMCG_CONFIG --api-version 2>/dev/null || echo 0`
        if test "$tmp" -gt 0 ; then
           AC_MSG_CHECKING([libTMCG API version])
           if test "$req_libtmcg_api" -eq "$tmp" ; then
             AC_MSG_RESULT(okay)
           else
             ok=no
             AC_MSG_RESULT([does not match (want=$req_libtmcg_api got=$tmp)])
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    LIBTMCG_CFLAGS=`$LIBTMCG_CONFIG --cflags`
    LIBTMCG_LIBS=`$LIBTMCG_CONFIG --libs`
    ifelse([$2], , :, [$2])
  else
    LIBTMCG_CFLAGS=""
    LIBTMCG_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBTMCG_CFLAGS)
  AC_SUBST(LIBTMCG_LIBS)
])
