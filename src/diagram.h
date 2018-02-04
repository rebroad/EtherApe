/* EtherApe
 * Copyright (C) 2000 Juan Toledo, Riccardo Ghetta
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

#ifndef DIAGRAM_H
#define DIAGRAM_H

#include "appdata.h"

extern gboolean already_updating; /* True while an instance of update_diagram is running */
extern gboolean stop_requested; /* True if there is a pending stop request */

gboolean update_diagram(gpointer data);
void init_diagram (GladeXML *xml);
void destroying_timeout (gpointer data);
void destroying_idle (gpointer data);
void set_statusbar_msg (gchar * str);
void delete_gui_protocols (void);
void ask_reposition(gboolean refresh_font); /* request diagram relayout */
void dump_stats(guint32 diff_msecs);
void timeout_changed(void);
void set_aa(void);
void redraw_canvas_background(GtkWidget *canvas); /* Called by on_canvas1_size_allocate */

#endif /* DIAGRAM_H */
