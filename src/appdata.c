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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include "appdata.h"
#include "stats/node.h"

#define ETHERAPE_GTKBUILDER_FILE  "etherape.ui" /* GtkBuilder file */

struct appdata_struct appdata;

void appdata_init(struct appdata_struct *p)
{
  gettimeofday(&p->gui_now, NULL);
  memset(&p->now, 0, sizeof(p->now));

  p->xml = NULL;
  p->app1 = NULL;
  p->statusbar = NULL;

  p->itf_file = NULL;
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
  if (p->source.type == ST_LIVE) {
    g_free(p->source.interface);
    p->source.interface = NULL;
  }
  else {
    g_free(p->source.file);
    p->source.file = NULL;
  }
}

gboolean appdata_init_builder(const gchar *builder_fname)
{
  GError *error = NULL;

  if (builder_fname)
    appdata.itf_file = g_strdup(builder_fname);
  else
    appdata.itf_file = g_strdup(GLADEDIR "/" ETHERAPE_GTKBUILDER_FILE);

  appdata.xml = gtk_builder_new();
  if (!gtk_builder_add_from_file(appdata.xml, appdata.itf_file, &error)) {
    g_error(_("Could not load interface file '%s'!: %s"),
            appdata.itf_file,
            error->message);
    g_error_free(error);
    return FALSE;
  }

  gtk_builder_connect_signals(appdata.xml, NULL);

  appdata.app1 = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "app1"));
  appdata.statusbar = GTK_STATUSBAR(gtk_builder_get_object(appdata.xml, "statusbar1"));
  return TRUE;
}

/* releases all memory allocated for internal fields */
void appdata_free(struct appdata_struct *p)
{
  appdata_clear_source(p);

  g_free(p->itf_file);
  p->itf_file = NULL;

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

