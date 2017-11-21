/*
 * pam_8021x: PAM module for authentication through 802.1x protocol
 * Copyright (C) 2014 Enrique Hernández Bello <ehbello@gmail.com>
 *
 * Inspired on pam_dbus: (C) Copyright Joachim Breitner <mail@joachim-breitner.de>
 * Inspired on add-connection-dbus-glib.c: (C) Copyright 2011 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <syslog.h>
#include <config.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-ip4-config.h>
#include <NetworkManager.h>
#include <nm-utils.h>

#define DBUS_TYPE_G_MAP_OF_VARIANT          (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT   (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT))

/*
 * Globals.
 */

static int debug;               /* Debug flag */
static int try_first_pass;      /* Try to obtain auth token from pam stack */

static void
add_connection (pam_handle_t *pamh, DBusGProxy *proxy, const char *con_name, 
  const char *con_identity,
  const char *con_pwd)
{
  NMConnection *connection;
  NMSettingConnection *s_con;
  NMSettingWired *s_wired;
  NMSetting8021x *s_8021x;
  NMSettingIP4Config *s_ip4;
  char *uuid, *new_con_path = NULL;
  GHashTable *hash;
  GError *error = NULL;

  /* Create a new connection object */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Creating new connection object.");
  }
  connection = (NMConnection *) nm_connection_new ();

  /* Build up the 'connection' Setting */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Building up the 'connection' setting.");
  }
  s_con = (NMSettingConnection *) nm_setting_connection_new ();
  uuid = nm_utils_uuid_generate ();
  g_object_set (G_OBJECT (s_con),
    NM_SETTING_CONNECTION_UUID, uuid,
    NM_SETTING_CONNECTION_ID, con_name,
    NM_SETTING_CONNECTION_TYPE, "802-3-ethernet",
    NULL);
  g_free (uuid);
  nm_connection_add_setting (connection, NM_SETTING (s_con));

  /* Build up the 'wired' Setting */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Building up the 'wired' setting.");
  }
  s_wired = (NMSettingWired *) nm_setting_wired_new ();
  nm_connection_add_setting (connection, NM_SETTING (s_wired));

  /* Build up the '8021x' Setting */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Building up the '8021x' setting.");
  }
  s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
  g_object_set (G_OBJECT (s_8021x),
    NM_SETTING_802_1X_SYSTEM_CA_CERTS, TRUE,
    NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS, TRUE,
    NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "anon@example.com",
    NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS, TRUE,
    NM_SETTING_802_1X_IDENTITY, con_identity,
    NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2",
    NM_SETTING_802_1X_PASSWORD, con_pwd,
    NULL);
  nm_setting_802_1x_add_phase2_altsubject_match(s_8021x, "DNS:radius.example.com");
  nm_setting_802_1x_add_eap_method(s_8021x, "peap");
  nm_connection_add_setting (connection, NM_SETTING (s_8021x));

  /* Build up the 'ipv4' Setting */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Building up the 'ipv4' setting.");
  }
  s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
  g_object_set (G_OBJECT (s_ip4),
    NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
    NULL);
  nm_connection_add_setting (connection, NM_SETTING (s_ip4));

  hash = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

  /* Call AddConnection with the hash as argument */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Calling AddConnection D-BUS method.");
  }
  if (!dbus_g_proxy_call (proxy, "AddConnection", &error,
    DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, hash,
    G_TYPE_INVALID,
    DBUS_TYPE_G_OBJECT_PATH, &new_con_path,
    G_TYPE_INVALID)) {
      g_print ("Error adding connection: %s %s",
      dbus_g_error_get_name (error),
      error->message);
      pam_syslog (pamh, LOG_ERR, "Error adding connection: %s %s",
      dbus_g_error_get_name (error),
      error->message);
    g_clear_error (&error);
  } else {
    g_print ("Added: %s\n", new_con_path);
    pam_syslog (pamh, LOG_ERR, "Added: %s\n", new_con_path);
    g_free (new_con_path);
  }

  g_hash_table_destroy (hash);
  g_object_unref (connection);
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv) {
  DBusGConnection *bus;
  DBusGProxy *proxy;

  GError *error;

  gboolean login_ok = TRUE;

  for (; argc-- > 0; ++argv)
  {
    if (!strncmp (*argv, "debug", 5))
    {
      debug++;
    }

    if (!strncmp (*argv, "try_first_pass", 14))
    {
      try_first_pass++;
    }
  }

  /* Initialize GType system */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Initializing GType system.");
  }
  g_type_init();

  /* Get system bus */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Getting system bus.");
  }
  error = NULL;
  bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
  if (bus == NULL) {
    g_error_free (error);
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Create a D-Bus proxy; NM_DBUS_* defined in NetworkManager.h */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Creating D-Bus proxy.");
  }
  proxy = dbus_g_proxy_new_for_name (bus,
    NM_DBUS_SERVICE,
    NM_DBUS_PATH_SETTINGS,
    NM_DBUS_IFACE_SETTINGS);

  const char *service, *username, *authtok;
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Getting items.");
  }
  pam_get_item (pamh, PAM_SERVICE, (const void **)&service);

  if (pam_get_user (pamh, &username, NULL) != PAM_SUCCESS)
  {
    pam_syslog (pamh, LOG_ERR, "Couldn't determine username.");
    return PAM_AUTHINFO_UNAVAIL;
  }

  /*
   * try_first_pass works with simple password authentication.
   */

  if (try_first_pass)
  {
    if (pam_get_item (pamh, PAM_AUTHTOK, (const void **)&authtok) != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "Couldn't obtain PAM_AUTHTOK from the pam stack.");
      authtok = NULL;
    }
  }

  if (authtok == NULL)
  {
    if (pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, (char **)&authtok, "Password:") != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "Couldn't obtain password from pam_prompt.");
      return PAM_AUTHINFO_UNAVAIL;
    }
  }

  /* Add a connection */
  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Adding network connection.");
  }
  add_connection (pamh, proxy, "__802.1x connection__", username, authtok);

  g_object_unref (proxy);
  dbus_g_connection_unref (bus);

  if (debug)
  {
    pam_syslog (pamh, LOG_INFO, "Authentication finished.");
  }

  //return login_ok ? PAM_SUCCESS : PAM_AUTH_ERR;
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
/*
  if (can_connect_8021x() == 0) {
    return PAM_SUCCESS;
  } else {
    return PAM_ABORT;
  }
*/
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}
