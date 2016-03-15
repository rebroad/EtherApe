/* EtherApe
 * Copyright (C) 2001 Juan Toledo
 * $Id$
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <gtk/gtk.h>
#include "preferences.h"
#include "math.h"
#include "datastructs.h"
#include "node.h"

struct pref_struct pref;
GList *centered_node_speclist = NULL;
static const gchar *pref_group = "Diagram";

/***************************************************************
 *
 * internal helpers
 *
 ***************************************************************/

static void read_string_config(gchar **item, GKeyFile *gkey, const char *key)
{
  gchar *tmp;
  tmp = g_key_file_get_string(gkey, pref_group, key, NULL);
  if (!tmp)
    return;

  /* frees previous value and sets to new pointer */
  g_free(*item);
  *item = tmp;
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

/***************************************************************
 *
 * pref handling
 *
 ***************************************************************/
void init_config(struct pref_struct *p)
{
  p->name_res = TRUE;
  p->refresh_period = 800;	/* ms */

  p->diagram_only = FALSE;
  p->group_unk = TRUE;
  p->stationary = FALSE;
  p->node_radius_multiplier = 0.0005;
  p->link_node_ratio = 1;
  p->inner_ring_scale = 0.5;
  p->size_mode = LINEAR;
  p->node_size_variable = INST_OUTBOUND;
  p->stack_level = 0;
  p->proto_timeout_time=0;
  p->gui_node_timeout_time=0;
  p->node_timeout_time=0;
  p->proto_node_timeout_time=0;
  p->gui_link_timeout_time=0;
  p->link_timeout_time=0;
  p->proto_link_timeout_time=0;
  p->refresh_period=0;
  p->pcap_stats_pos = STATSPOS_NONE;

  p->filter = NULL;
  p->text_color=NULL;
  p->fontname=NULL;
  p->colors=NULL;
  p->centered_nodes = NULL;
  p->bck_image_path = NULL;
  p->bck_image_enabled = FALSE;

  p->show_statusbar = TRUE;
  p->show_toolbar = TRUE;
  p->show_legend = TRUE;

  p->averaging_time=3000;
  p->position = NULL;
}

void set_default_config(struct pref_struct *p)
{
  p->diagram_only = FALSE;
  p->group_unk = TRUE;
  p->stationary = FALSE;
  p->name_res = TRUE;
  p->node_timeout_time = 120000.0;
  p->gui_node_timeout_time = 60000.0;
  p->proto_node_timeout_time = 60000.0;
  p->link_timeout_time = 20000.0;
  p->gui_link_timeout_time = 20000.0;
  p->proto_link_timeout_time = 20000.0;
  p->proto_timeout_time = 600000.0;
  p->averaging_time = 2000.0;
  p->node_radius_multiplier = 0.0005;
  p->link_node_ratio = 1.0;
  p->inner_ring_scale = 0.5;
  p->refresh_period = 100;
  p->size_mode = LINEAR;
  p->node_size_variable = INST_OUTBOUND;
  p->stack_level = 0;
  p->pcap_stats_pos = STATSPOS_NONE;

  g_free(p->filter);
  p->filter = g_strdup("ip or ip6");

  g_free(p->fontname);
  p->fontname = g_strdup("Sans 8");

  g_free(p->text_color);
  p->text_color = g_strdup("#ffff00");

  g_strfreev(p->colors);
  p->colors = g_strsplit("#ff0000;WWW,HTTP #0000ff;DOMAIN #00ff00 #ffff00 "
                           "#ff00ff #00ffff #ffffff #ff7700 #ff0077 #ffaa77 "
                           "#7777ff #aaaa33",
                           " ", 0);
  p->colors = protohash_compact(p->colors);
  protohash_read_prefvect(p->colors);

  g_free(p->centered_nodes);
  p->centered_nodes = g_strdup("");

  p->bck_image_enabled = FALSE;
  g_free(p->bck_image_path);
  p->bck_image_path = g_strdup("");

  p->show_statusbar = TRUE;
  p->show_toolbar = TRUE;
  p->show_legend = TRUE;
}

/* loads configuration from .gnome/Etherape */
void load_config(struct pref_struct *p)
{
  gchar *pref_file;
  gchar *tmpstr = NULL;
  gchar **colorarray;
  GKeyFile *gkey;

  /* first reset configurations to defaults */
  set_default_config(p);

  gkey = g_key_file_new();

  /* tries to read config from file (~/.config/etherape) */
  pref_file = config_file_name();
  if (!g_key_file_load_from_file(gkey, pref_file, G_KEY_FILE_NONE, NULL))
    {
      /* file not found, try old location (~/.gnome2/Etherape) */
      g_free(pref_file);
      pref_file = old_config_file_name();
      if (!g_key_file_load_from_file(gkey, pref_file, G_KEY_FILE_NONE, NULL))
        {
          g_free(pref_file);
          return;
        }
    }
  g_free(pref_file);

  read_string_config(&p->filter, gkey, "filter");
  read_string_config(&p->fontname, gkey, "fontname");
  read_string_config(&p->text_color, gkey, "text_color");
  read_string_config(&p->centered_nodes, gkey, "centered_nodes");
  centered_node_speclist = parse_nodeset_spec_list(p->centered_nodes);

  read_boolean_config(&p->bck_image_enabled, gkey, "bck_image_enabled");
  read_string_config(&p->bck_image_path, gkey, "bck_image_path");

  read_boolean_config(&p->diagram_only, gkey, "diagram_only");
  read_boolean_config(&p->group_unk, gkey, "group_unk");
  read_boolean_config(&p->stationary, gkey, "stationary");
  read_boolean_config(&p->name_res, gkey, "name_res");
  read_int_config((gint *)&p->refresh_period, gkey, "refresh_period");
  read_int_config((gint *)&p->size_mode, gkey, "size_mode");
  read_int_config((gint *)&p->node_size_variable, gkey, "node_size_variable");
  read_int_config((gint *)&p->stack_level, gkey, "stack_level");
  read_int_config((gint *)&p->pcap_stats_pos, gkey, "pcap_stats_pos");

  read_double_config(&p->node_timeout_time, gkey, "node_timeout_time");
  read_double_config(&p->gui_node_timeout_time, gkey, "gui_node_timeout_time");
  read_double_config(&p->proto_node_timeout_time, gkey, "proto_node_timeout_time");
  read_double_config(&p->link_timeout_time, gkey, "link_timeout_time");
  read_double_config(&p->gui_link_timeout_time, gkey, "gui_link_timeout_time");
  read_double_config(&p->proto_link_timeout_time, gkey, "proto_link_timeout_time");
  read_double_config(&p->proto_timeout_time, gkey, "proto_timeout_time");
  read_double_config(&p->averaging_time, gkey, "averaging_time");
  read_double_config(&p->node_radius_multiplier, gkey, "node_radius_multiplier");
  read_double_config(&p->link_node_ratio, gkey, "link_node_ratio");
  read_double_config(&p->inner_ring_scale, gkey, "inner_ring_scale");

  read_boolean_config(&p->show_statusbar, gkey, "show_statusbar");
  read_boolean_config(&p->show_toolbar, gkey, "show_toolbar");
  read_boolean_config(&p->show_legend, gkey, "show_legend");

  read_string_config(&tmpstr, gkey, "colors");
  if (tmpstr)
    {
      colorarray = g_strsplit(tmpstr, " ", 0);
      if (colorarray)
        {
          g_strfreev(p->colors);
          p->colors = protohash_compact(colorarray);
          protohash_read_prefvect(p->colors);
        }
      g_free(tmpstr);
    }

  /* if needed, read the config version 
  version = g_key_file_get_string(gkey, "General", "version");
  ... do processing here ...
  g_free(version);
  */

  g_key_file_free(gkey);
}

/* saves configuration to .gnome/Etherape */
/* It's not static since it will be called from the GUI */
void save_config(const struct pref_struct *p)
{
  gchar *pref_file;
  gchar *cfgdata;
  gchar *tmpstr;
  gboolean res;
  GError *error = NULL;
  GKeyFile *gkey;

  gkey = g_key_file_new();

  g_key_file_set_boolean(gkey, pref_group, "diagram_only", p->diagram_only);
  g_key_file_set_boolean(gkey, pref_group, "group_unk", p->group_unk);
  g_key_file_set_boolean(gkey, pref_group, "name_res", p->name_res);
  g_key_file_set_double(gkey, pref_group, "node_timeout_time",
                        p->node_timeout_time);
  g_key_file_set_double(gkey, pref_group, "gui_node_timeout_time",
                        p->gui_node_timeout_time);
  g_key_file_set_double(gkey, pref_group, "proto_node_timeout_time",
                        p->proto_node_timeout_time);
  g_key_file_set_double(gkey, pref_group, "link_timeout_time",
                        p->link_timeout_time);
  g_key_file_set_double(gkey, pref_group, "gui_link_timeout_time",
                        p->gui_link_timeout_time);
  g_key_file_set_double(gkey, pref_group, "proto_link_timeout_time",
                        p->proto_link_timeout_time);
  g_key_file_set_double(gkey, pref_group, "proto_timeout_time",
                        p->proto_timeout_time);
  g_key_file_set_double(gkey, pref_group, "averaging_time", p->averaging_time);
  g_key_file_set_double(gkey, pref_group, "node_radius_multiplier",
                        p->node_radius_multiplier);
  g_key_file_set_double(gkey, pref_group, "link_node_ratio",
                        p->link_node_ratio);
  g_key_file_set_double(gkey, pref_group, "inner_ring_scale",
                        p->inner_ring_scale);
  g_key_file_set_integer(gkey, pref_group, "refresh_period", p->refresh_period);
  g_key_file_set_integer(gkey, pref_group, "size_mode", p->size_mode);
  g_key_file_set_integer(gkey, pref_group, "node_size_variable",
                         p->node_size_variable);
  g_key_file_set_integer(gkey, pref_group, "stack_level", p->stack_level);
  g_key_file_set_integer(gkey, pref_group, "pcap_stats_pos", p->pcap_stats_pos);

  g_key_file_set_string(gkey, pref_group, "filter", p->filter);
  g_key_file_set_string(gkey, pref_group, "fontname", p->fontname);
  g_key_file_set_string(gkey, pref_group, "text_color", p->text_color);
  g_key_file_set_string(gkey, pref_group, "centered_nodes", p->centered_nodes);

  g_key_file_set_boolean(gkey, pref_group, "bck_image_enabled", p->bck_image_enabled);
  g_key_file_set_string(gkey, pref_group, "bck_image_path", p->bck_image_path);

  g_key_file_set_boolean(gkey, pref_group, "show_statusbar", p->show_statusbar);
  g_key_file_set_boolean(gkey, pref_group, "show_toolbar", p->show_toolbar);
  g_key_file_set_boolean(gkey, pref_group, "show_legend", p->show_legend);

  tmpstr = g_strjoinv(" ", p->colors);
  g_key_file_set_string(gkey, pref_group, "colors", tmpstr);
  g_free(tmpstr);

  g_key_file_set_string(gkey, "General", "version", VERSION);

  /* write config to file */
  cfgdata = g_key_file_to_data(gkey, NULL, NULL);
  pref_file = config_file_name();
  res = g_file_set_contents(pref_file, cfgdata, -1, &error);
  g_free(cfgdata);

  if (res)
    g_my_info (_("Preferences saved to %s"), pref_file);
  else
    {
      GtkWidget *dialog = gtk_message_dialog_new (NULL,
                             GTK_DIALOG_DESTROY_WITH_PARENT,
                             GTK_MESSAGE_ERROR,
                             GTK_BUTTONS_CLOSE,
                             _("Error saving preferences to '%s': %s"),
                             pref_file,
                             (error && error->message) ? error->message : "");
      gtk_dialog_run (GTK_DIALOG (dialog));
      gtk_widget_destroy (dialog);
    }
  g_free(pref_file);
  g_key_file_free(gkey);
}

/* duplicates a config */
struct pref_struct *
duplicate_config(const struct pref_struct *src)
{
  struct pref_struct *t;

  t = g_malloc(sizeof(struct pref_struct));
  g_assert(t);

  t->filter = NULL;
  t->text_color = NULL;
  t->fontname = NULL;
  t->colors = NULL;
  t->centered_nodes = NULL;
  t->bck_image_path = NULL;
  copy_config(t, src);

  return t;
}

/* releases all memory allocated for internal fields */
void free_config(struct pref_struct *t)
{
  g_free(t->filter);
  t->filter=NULL;
  g_free(t->text_color);
  t->text_color=NULL;
  g_free(t->fontname);
  t->fontname=NULL;
  g_free(t->centered_nodes);
  t->centered_nodes=NULL;
  g_free(t->bck_image_path);
  t->bck_image_path=NULL;

  g_strfreev(t->colors);
  t->colors = NULL;
}

/* copies a configuration from src to tgt */
void copy_config(struct pref_struct *tgt, const struct pref_struct *src)
{
  if (tgt == src)
	return;

  /* first, reset old data */
  free_config(tgt);

  /* then copy */
  tgt->name_res=src->name_res;
  tgt->diagram_only = src->diagram_only;
  tgt->group_unk = src->group_unk;
  tgt->stationary = src->stationary;
  tgt->node_radius_multiplier = src->node_radius_multiplier;
  tgt->link_node_ratio = src->link_node_ratio;
  tgt->inner_ring_scale = src->inner_ring_scale;
  tgt->size_mode = src->size_mode;
  tgt->node_size_variable = src->node_size_variable;
  tgt->pcap_stats_pos = src->pcap_stats_pos;
  tgt->filter=g_strdup(src->filter);
  tgt->text_color=g_strdup(src->text_color);
  tgt->fontname=g_strdup(src->fontname);
  tgt->centered_nodes=g_strdup(src->centered_nodes);
  tgt->bck_image_enabled = src->bck_image_enabled;
  tgt->bck_image_path = g_strdup(src->bck_image_path);
  tgt->stack_level = src->stack_level;
  tgt->colors = g_strdupv(src->colors);

  tgt->show_statusbar = src->show_statusbar;
  tgt->show_toolbar = src->show_toolbar;
  tgt->show_legend = src->show_legend;

  tgt->proto_timeout_time = src->proto_timeout_time;
  tgt->gui_node_timeout_time = src->gui_node_timeout_time;
  tgt->node_timeout_time = src->node_timeout_time;
  tgt->proto_node_timeout_time = src->proto_node_timeout_time;
  tgt->gui_link_timeout_time = src->gui_link_timeout_time;
  tgt->link_timeout_time = src->link_timeout_time;
  tgt->proto_link_timeout_time = src->proto_link_timeout_time;

  tgt->refresh_period = src->refresh_period;
  tgt->averaging_time = src->averaging_time;
  tgt->position = g_strdup(src->position);
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

  init_config(&tmp_prefs);

  load_config(&tmp_prefs);

  edit(&tmp_prefs, data);

  save_config(&tmp_prefs);

  free_config(&tmp_prefs);
}
