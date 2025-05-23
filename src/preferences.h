/* EtherApe
 * Copyright (C) 2000 Juan Toledo
 * Copyright (C) 2011 Riccardo Ghetta
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

#ifndef PREFERENCES_H
#define PREFERENCES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "common.h"

/*
 * Preferences data.
 *
 * Note that this is strictly for options that live in the config file;
 * options set by command-line flags should go elsewhere.
 */
struct pref_struct
{
  gboolean name_res;            /* Whether dns lookups are performed */
  gboolean diagram_only;        /* Do not use text on the diagram */
  gboolean group_unk;           /* Whether to display as one every unkown port protocol */
  gboolean headless;            /* don't update display (TODO: implement a proper text mode) */
  gdouble node_radius_multiplier;       /* used to calculate the radius of the
                                         * displayed nodes. So that the user can
                                         * select with certain precision this
                                         * value, the GUI uses the log10 of the
                                         * multiplier */
  gdouble inner_ring_scale; /* scale of inner ring in proportion to outer ring */
  size_mode_t size_mode;        /* Default mode for node size and
                                 * link width calculation */
  node_size_variable_t node_size_variable;      /* Default variable that sets the node
                                                 * size */
  gchar *filter;                /* Pcap filter to be used */
  gchar *text_color;            /* text color */
  gchar *fontname;              /* Font to be used for text display */
  gchar *centered_nodes;        /* Name/IP/CIDR-range of nodes to center (optional) */
  guint stack_level;            /* Which level of the protocol stack
                                 * we will concentrate on */

  gboolean bck_image_enabled; /* Whether or not to use a background image */
  gchar *bck_image_path;    /* Path to the background image (optional) */

  /* Whether or not these respective UI elements are shown */
  gboolean show_statusbar;
  gboolean show_toolbar;
  gboolean show_legend;

  statspos_t pcap_stats_pos; /* Position at which to display pcap stats */

  /* after this time has passed without traffic on a protocol, it's removed
   * from the global protocol stats */
  gdouble proto_timeout_time;

  /* After this time has passed with no traffic for a node, it
   * disappears from the diagram */
  gdouble gui_node_timeout_time;

  /* After this time has passed with no traffic for a node, it
  * is deleted from memory */
  gdouble proto_node_timeout_time;

  gchar * *colors;       /* list of colors to be used on the diagram. Format is
                         * color[;protocol[,protocol ...]] [color[;protocol] ...
                         * where color is represented by sis hex digits (RGB) */

  /* After this time has passed with no traffic for a link, it
   * disappears from the diagram */
  gdouble gui_link_timeout_time;

  /* after this time has passed without traffic, the link is removed */
  gdouble proto_link_timeout_time;

  guint32 refresh_period;       /* Time between diagram refreshes */
  gdouble averaging_time;       /* Microseconds of time we consider to
                                 * calculate traffic averages */
};

extern struct pref_struct pref;

/* Parsed version pref.centered_nodes */
extern GList *centered_node_speclist;

/* preferences methods */
gboolean load_config(struct pref_struct *p);
void save_config(const struct pref_struct *p);
void free_config(struct pref_struct *t);
void copy_config(struct pref_struct *tgt, const struct pref_struct *src);

typedef void (*config_edit_fn)(struct pref_struct *p, void *data);
void mutate_saved_config(config_edit_fn edit, void *data);

#endif
