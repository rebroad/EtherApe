/* EtherApe
 * Copyright (C) 2001 Juan Toledo
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "appdata.h"
#include "stats/node.h"

#define ETHERAPE_GLADE_FILE "etherape.glade"	/* glade 3 file */

struct appdata_struct appdata;

void appdata_init(struct appdata_struct *p)
{
  gettimeofday(&p->gui_now, NULL);
  memset(&p->now, 0, sizeof(p->now));

  p->xml = NULL;
  p->app1 = NULL;
  p->statusbar = NULL;

  p->glade_file = NULL;
  p->export_file = NULL;
  p->export_file_final = NULL;
  p->export_file_signal = NULL;

  p->source.type = ST_LIVE;
  p->source.interface = NULL;

  p->mode = IP;
  p->node_limit = -1;
  p->debug_mask = (G_LOG_LEVEL_MASK & ~(G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO));
  p->min_delay = 0;
  p->max_delay = G_MAXULONG;
  p->stationary_layout = FALSE;

  p->n_packets = 0;
  p->total_mem_packets = 0;
  p->request_dump = FALSE;

  p->column_patterns = NULL;
}

void appdata_clear_source(struct appdata_struct *p)
{
  if (p->source.type == ST_LIVE)
    {
      g_free(p->source.interface);
      p->source.interface = NULL;
    }
  else
    {
      g_free(p->source.file);
      p->source.file = NULL;
    }
}

gboolean appdata_init_glade(gchar *new_glade_file)
{
  if (new_glade_file)
    appdata.glade_file = g_strdup(new_glade_file);
  else
    appdata.glade_file = g_strdup(GLADEDIR "/" ETHERAPE_GLADE_FILE);

  appdata.xml = glade_xml_new (appdata.glade_file, NULL, NULL);
  if (!appdata.xml)
    {
      g_error (_("Could not load glade interface file '%s'!"),
	       appdata.glade_file);
      return FALSE;
    }
  glade_xml_signal_autoconnect (appdata.xml);

  appdata.app1 = glade_xml_get_widget (appdata.xml, "app1");
  appdata.statusbar = GTK_STATUSBAR(glade_xml_get_widget (appdata.xml, "statusbar1"));
  return TRUE;
}

/* releases all memory allocated for internal fields */
void appdata_free(struct appdata_struct *p)
{
  appdata_clear_source(p);

  g_free(p->glade_file);
  p->glade_file = NULL;

  g_free(p->export_file);
  p->export_file = NULL;

  g_free(p->export_file_final);
  p->export_file_final = NULL;

  g_free(p->export_file_signal);
  p->export_file_signal = NULL;

  if (p->column_patterns) {
    int pos;
    for (pos = 0; pos < p->column_patterns->len; ++pos) {
       free_nodeset_spec_list(g_ptr_array_index(p->column_patterns, pos));
    }
    g_ptr_array_free(p->column_patterns, TRUE);
    p->column_patterns = NULL;
  }

  /* no need to free glade widgets ... */
}

