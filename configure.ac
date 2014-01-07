# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# $Id: $

# This file is part of pam_8021x.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

AC_INIT([pam_8021x], [0.1], [Enrique Hernández Bello <ehbello@gmail.com>])
AC_CONFIG_HEADER(config.h)

AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/pam_8021x.c])

AC_PREREQ([2.13])
AC_PROG_CC
AM_PROG_CC_C_O

AC_CHECK_HEADER([security/pam_modules.h], ,
	[AC_MSG_ERROR([PAM headers missing])])
AC_CHECK_LIB(pam, pam_start, [PAM_LIBS="-lpam"],
	AC_MSG_ERROR([PAM library missing]))
AC_SUBST(PAM_LIBS)

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.10, dummy=yes,
                                AC_MSG_ERROR(libglib-2.0 is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.0, dummy=yes,
                                AC_MSG_ERROR(libdbus is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1 >= 0.70, dummy=yes,
                                AC_MSG_ERROR(libdbus-glib is required))
AC_SUBST(DBUS_GLIB_CFLAGS)
AC_SUBST(DBUS_GLIB_LIBS)

PKG_CHECK_MODULES(NM, NetworkManager >= 0.9 libnm-util >= 0.9, dummy=yes,
                                AC_MSG_ERROR(libnm-util is required))
AC_SUBST(NM_CFLAGS)
AC_SUBST(NM_LIBS)

AC_CONFIG_FILES([Makefile] [src/Makefile])
AC_OUTPUT
