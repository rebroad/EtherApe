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
#include "callbacks.h"

extern gboolean already_updating; /* True while an instance of update_diagram is running */
extern gboolean stop_requested; /* True if there is a pending stop request */

gboolean update_diagram_callback(gpointer data);
gboolean refresh_diagram(void);
void init_diagram(GtkBuilder *xml);
void cleanup_diagram();         /* free static data */
void set_statusbar_msg(gchar *str);
void delete_gui_protocols(void);
void dump_stats(guint32 diff_msecs);
void diagram_timeout_changed(void);
void resize_diagram(const GtkAllocation *allocation);
void ask_reposition(gboolean refresh_font); /* request diagram relayout */
GtkWidget *canvas_widget();

#endif /* DIAGRAM_H */
