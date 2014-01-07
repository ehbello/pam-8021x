pammod_PROGRAMS = pam_8021x.so
pammoddir=/lib/security

pam_8021x_so_SOURCES = pam_8021x.c
pam_8021x_so_CFLAGS = -fPIC $(PAM_CFLAGS) $(GLIB_CFLAGS) $(DBUS_CFLAGS) $(DBUS_GLIB_CFLAGS) $(NM_CFLAGS)
pam_8021x_so_LDFLAGS = -shared
pam_8021x_so_LDADD = $(PAM_LIBS) $(GLIB_LIBS) $(DBUS_LIBS) $(DBUS_GLIB_LIBS) $(NM_LIBS)

