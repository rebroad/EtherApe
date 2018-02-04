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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gtk/gtk.h>
#include <goocanvas.h>
#include "appdata.h"
#include "callbacks.h"
#include "diagram.h"
#include "preferences.h"

void on_canvas1_size_allocate(GtkWidget *widget,
			      									GtkAllocation *allocation,
															gpointer user_data)
{
	resize_diagram(allocation);
}

/* TODO this is not necessary, can be set directly in etherape.glade */
gboolean on_node_popup_motion_notify_event(GtkWidget *widget,
				   																 GdkEventMotion *event,
																					 gpointer user_data)
{
  gtk_widget_destroy (widget);
  return FALSE;
}

gboolean on_name_motion_notify_event(GtkWidget *widget,
			     													 GdkEventMotion *event,
																		 gpointer user_data)
{
  g_message ("Motion in name label");
  return FALSE;
}
