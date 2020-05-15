/* EtherApe
 * Copyright (C) 2001 Juan Toledo, Riccardo Ghetta
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif
#include <gtk/gtk.h>
#include "preferences.h"
#include "math.h"
#include "datastructs.h"
#include "stats/node.h"

struct pref_struct pref;
GList *centered_node_speclist = NULL;
static const gchar *pref_group = "Diagram";

/* Separator character used in encoding string-vectors */
#define STRVEC_SEP  " "

/***************************************************************
 *
 * internal helpers
 *
 ***************************************************************/

static void read_string_config(gchar * *item, GKeyFile *gkey, const char *key)
{
  gchar *tmp;
  tmp = g_key_file_get_string(gkey, pref_group, key, NULL);
  if (!tmp)
    return;

  /* frees previous value and sets to new pointer */
  g_free(*item);
  *item = tmp;
}

static void read_strvec_config(gchar * * *item, GKeyFile *gkey, const char *key)
{
  gchar *tmp = NULL;
  read_string_config(&tmp, gkey, key);
  if (tmp) {
    g_strfreev(*item);
    *item = g_strsplit(tmp, STRVEC_SEP, 0);
    g_free(tmp);
  }
}

static void read_boolean_config(gboolean *item, GKeyFile *gkey, const char *key)
{
  gboolean tmp;
  GError *err = NULL;
  tmp = g_key_file_get_boolean(gkey, pref_group, key, &err);
  if (err)
    return; /* key not found, exit */
  *item = tmp;
}

static void read_int_config(gint *item, GKeyFile *gkey, const char *key)
{
  gint tmp;
  GError *err = NULL;
  tmp = g_key_file_get_integer(gkey, pref_group, key, &err);
  if (err)
    return; /* key not found, exit */
  *item = tmp;
}

static void read_double_config(gdouble *item, GKeyFile *gkey, const char *key)
{
  gdouble tmp;
  GError *err = NULL;
  tmp = g_key_file_get_double(gkey, pref_group, key, &err);
  if (err)
    return; /* key not found, exit */
  *item = tmp;
}

static gchar *config_file_name(void)
{
  return g_strdup_printf("%s/%s", g_get_user_config_dir(), "etherape");
}
static gchar *old_config_file_name(void)
{
  return g_strdup_printf("%s/.gnome2/Etherape", g_get_home_dir());
}

typedef enum
{
  PT_bool,
  PT_int,
  PT_double,
  PT_string,
  PT_strvec,
} preftype_t;

/* Describes a setting in the config file */
struct preference
{
  /* Label used in the config file */
  const char *name;

  /* where it sits within pref_struct */
  ptrdiff_t offset;

  /* What type of setting it is */
  preftype_t type;

  /* Default value for the setting */
  union
  {
    gboolean pv_bool;
    gint pv_int;
    gdouble pv_double;
    gchar *pv_string;
    gchar * *pv_strvec;
  } defval;
};

#define MKPREF(n, t, d)  { \
    .name = #n, \
    .offset = offsetof(struct pref_struct, n), \
    .type = PT_ ## t, \
    .defval.pv_ ## t = d, \
}

static const struct preference preferences[] = {
  MKPREF(name_res, bool, TRUE),
  MKPREF(diagram_only, bool, FALSE),
  MKPREF(group_unk, bool, TRUE),
  MKPREF(centered_nodes, string, ""),

  MKPREF(text_color, string, "#ffff00"),
  MKPREF(fontname, string, "Sans 8"),
  MKPREF(colors, strvec, ((char *[]) {"#ff0000;WWW,HTTP,HTTPS", "#0000ff;DOMAIN",
                                      "#00ff00", "#ffff00", "#ff00ff",
                                      "#00ffff;ICMP,ICMPV6",
                                      "#ffffff", "#ff7700", "#ff0077", "#ffaa77",
                                      "#7777ff", "#aaaa33", NULL, })),

  MKPREF(bck_image_enabled, bool, TRUE),
  MKPREF(bck_image_path, string, ""),

  MKPREF(show_statusbar, bool, TRUE),
  MKPREF(show_toolbar, bool, TRUE),
  MKPREF(show_legend, bool, TRUE),

  MKPREF(inner_ring_scale, double, 0.5),
  MKPREF(node_radius_multiplier, double, 0.0005),
  MKPREF(link_node_ratio, double, 1.0),
  MKPREF(node_size_variable, int, INST_OUTBOUND),
  MKPREF(size_mode, int, LINEAR),

  MKPREF(node_timeout_time, double, 120000.0),
  MKPREF(gui_node_timeout_time, double, 60000.0),
  MKPREF(proto_node_timeout_time, double, 0),

  MKPREF(link_timeout_time, double, 20000.0),
  MKPREF(gui_link_timeout_time, double, 20000.0),
  MKPREF(proto_link_timeout_time, double, 600000.0),

  MKPREF(proto_timeout_time, double, 60000.0),
  MKPREF(refresh_period, int, 100),
  MKPREF(averaging_time, double, 2000.0),

  MKPREF(filter, string, "ip or ip6"),
  MKPREF(pcap_stats_pos, int, STATSPOS_NONE),
  MKPREF(stack_level, int, 0),
};

#define NUM_PREFS  (sizeof(preferences) / sizeof(preferences[0]))

/***************************************************************
 *
 * pref handling
 *
 ***************************************************************/
static void default_config(struct pref_struct *p)
{
  int i;
  void *addr;
  gchar *tmp;

  for (i = 0; i < NUM_PREFS; i++) {
    addr = (char *)p + preferences[i].offset;
    switch (preferences[i].type)
    {
        case PT_bool:
          *(gboolean *)addr = preferences[i].defval.pv_bool;
          break;

        case PT_int:
          *(gint *)addr = preferences[i].defval.pv_int;
          break;

        case PT_double:
          *(gdouble *)addr = preferences[i].defval.pv_double;
          break;

        case PT_string:
          *(gchar * *)addr = g_strdup(preferences[i].defval.pv_string);
          break;

        case PT_strvec:
          /*
           * Slightly clunky join-and-re-split dance so that the initialized
           * result is a g_strfreev()-able string vector.
           */
          tmp = g_strjoinv(STRVEC_SEP, preferences[i].defval.pv_strvec);
          *(gchar * * *)addr = g_strsplit(tmp, STRVEC_SEP, 0);
          g_free(tmp);
          break;
    }
  }
}

/* loads configuration from .gnome/Etherape */
void load_config(struct pref_struct *p)
{
  gchar *pref_file;
  GKeyFile *gkey;
  int i;
  void *addr;

  /* first set up defaults */
  default_config(p);

  gkey = g_key_file_new();

  /* tries to read config from file (~/.config/etherape) */
  pref_file = config_file_name();
  if (!g_key_file_load_from_file(gkey, pref_file, G_KEY_FILE_NONE, NULL)) {
    /* file not found, try old location (~/.gnome2/Etherape) */
    g_free(pref_file);
    pref_file = old_config_file_name();
    if (!g_key_file_load_from_file(gkey, pref_file, G_KEY_FILE_NONE, NULL)) {
      g_free(pref_file);
      return;
    }
  }
  g_free(pref_file);

  for (i = 0; i < NUM_PREFS; i++) {
    addr = (char *)p + preferences[i].offset;
    switch (preferences[i].type)
    {
        case PT_bool:
          read_boolean_config(addr, gkey, preferences[i].name);
          break;

        case PT_int:
          read_int_config(addr, gkey, preferences[i].name);
          break;

        case PT_double:
          read_double_config(addr, gkey, preferences[i].name);
          break;

        case PT_string:
          read_string_config(addr, gkey, preferences[i].name);
          break;

        case PT_strvec:
          read_strvec_config(addr, gkey, preferences[i].name);
          break;
    }
  }

  p->colors = protohash_compact(p->colors);

  g_key_file_free(gkey);
}

/* saves configuration to .gnome/Etherape */
/* It's not static since it will be called from the GUI */
void save_config(const struct pref_struct *p)
{
  int i;
  gchar *pref_file;
  gchar *cfgdata;
  gchar *tmp;
  const gchar *name;
  gboolean res;
  GError *error = NULL;
  GKeyFile *gkey;
  void *addr;

  gkey = g_key_file_new();

  for (i = 0; i < NUM_PREFS; i++) {
    addr = (char *)p + preferences[i].offset;
    name = preferences[i].name;
    switch (preferences[i].type)
    {
        case PT_bool:
          g_key_file_set_boolean(gkey, pref_group, name, *(gboolean *)addr);
          break;

        case PT_int:
          g_key_file_set_integer(gkey, pref_group, name, *(gint *)addr);
          break;

        case PT_double:
          g_key_file_set_double(gkey, pref_group, name, *(gdouble *)addr);
          break;

        case PT_string:
          g_key_file_set_string(gkey, pref_group, name, *(gchar * *)addr);
          break;

        case PT_strvec:
          tmp = g_strjoinv(STRVEC_SEP, *(gchar * * *)addr);
          g_key_file_set_string(gkey, pref_group, preferences[i].name, tmp);
          g_free(tmp);
          break;
    }
  }

  g_key_file_set_string(gkey, "General", "version", VERSION);

  /* write config to file */
  cfgdata = g_key_file_to_data(gkey, NULL, NULL);
  pref_file = config_file_name();
  res = g_file_set_contents(pref_file, cfgdata, -1, &error);
  g_free(cfgdata);

  if (res)
    g_my_info(_("Preferences saved to %s"), pref_file);
  else {
    GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                               GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                               _("Error saving preferences to '%s': %s"),
                                               pref_file, error->message);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
  }
  g_free(pref_file);
  g_key_file_free(gkey);
}

/* releases all memory allocated for internal fields */
void free_config(struct pref_struct *p)
{
  int i;
  void *addr;

  for (i = 0; i < NUM_PREFS; i++) {
    addr = (char *)p + preferences[i].offset;
    switch (preferences[i].type)
    {
        case PT_string:
          g_free(*(gchar * *)addr);
          *(gchar * *)addr = NULL;
          break;

        case PT_strvec:
          g_strfreev(*(gchar * * *)addr);
          *(gchar * * *)addr = NULL;
          break;

        default:
          break;
    }
  }
}

/* copies a configuration from src to tgt */
void copy_config(struct pref_struct *tgt, const struct pref_struct *src)
{
  int i;
  void *src_addr;
  void *tgt_addr;

  for (i = 0; i < NUM_PREFS; i++) {
    src_addr = (char *)src + preferences[i].offset;
    tgt_addr = (char *)tgt + preferences[i].offset;
    switch (preferences[i].type)
    {
        case PT_bool:
          *(gboolean *)tgt_addr = *(gboolean *)src_addr;
          break;

        case PT_int:
          *(gint *)tgt_addr = *(gint *)src_addr;
          break;

        case PT_double:
          *(gdouble *)tgt_addr = *(gdouble *)src_addr;
          break;

        case PT_string:
          *(gchar * *)tgt_addr = g_strdup(*(gchar * *)src_addr);
          break;

        case PT_strvec:
          *(gchar * * *)tgt_addr = g_strdupv(*(gchar * * *)src_addr);
          break;
    }
  }
}

/*
 * Sometimes (when showing/hiding statusbar, toolbar, or legend, specifically)
 * we want to update the saved form of a single preference setting in-place
 * without updating any others (to avoid implicitly doing an unwanted 'save'
 * operation on unsaved preference changes).  This function thus loads the
 * saved preferences into a temporary pref_struct, performs a given
 * modification on it via the supplied 'edit' function (to which the arbitrary
 * pointer 'data' is also passed), and then saves it.
 */
void mutate_saved_config(config_edit_fn edit, void *data)
{
  struct pref_struct tmp_prefs;

  load_config(&tmp_prefs);

  edit(&tmp_prefs, data);

  save_config(&tmp_prefs);

  free_config(&tmp_prefs);
}
