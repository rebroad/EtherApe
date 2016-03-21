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
 
#ifndef ETHERAPE_GLOBALS_H
#define ETHERAPE_GLOBALS_H

#include "common.h"
#include <glib/gprintf.h>
#include <glade/glade.h>
#include <gtk/gtk.h>

/* Variables */

struct appdata_struct
{
  GladeXML *xml;
  GtkWidget *app1;		/* Pointer to the main app window */
  GtkStatusbar *statusbar;        /* Main window statusbar */

  /* These two are different for offline (file-based) capture/replay */
  struct timeval now; /* Where in packet-capture time we are */
  struct timeval gui_now; /* Real (as in wall-clock gettimeofday()) time */

  gchar *glade_file;            /* fullspec of xml glade file */
  gchar *export_file;		/* file to export to */
  gchar *export_file_final;     /* file to export to at end of replay */
  gchar *export_file_signal;    /* file to export to at receipt of usr1 */
  apemode_t mode;		/* Mode of operation. Can be
				 * T.RING/FDDI/ETHERNET, IP or TCP */

  gint node_limit;		/* Max number of nodes to show. If <0 it's not
				 * limited */

  struct
  {
    enum { ST_FILE, ST_LIVE, } type;
    union
    {
      gchar *interface; /* Network interface to listen to */
      gchar *file;      /* Capture file to read from */
    };
  } source;

  GLogLevelFlags debug_mask;    /* debug mask active */

  gulong min_delay;    /* min packet distance when replaying a file */
  gulong max_delay;    /* max packet distance when replaying a file */


  unsigned long n_packets;	/* Number of total packets received */
  glong total_mem_packets;      /* Number of packets currently in memory */
  gboolean request_dump;        /* if true, do an xml dump */
};

extern struct appdata_struct appdata;

#define DEBUG_ENABLED  (appdata.debug_mask & G_LOG_LEVEL_DEBUG)
#define INFO_ENABLED  (appdata.debug_mask & G_LOG_LEVEL_INFO)

void appdata_init(struct appdata_struct *p);
void appdata_clear_source(struct appdata_struct *p);
gboolean appdata_init_glade(gchar *new_glade_file);
void appdata_free(struct appdata_struct *p);

static inline gchar *appdata_source_name(const struct appdata_struct *p)
{
  return p->source.type == ST_LIVE ? p->source.interface : p->source.file;
}

#endif
