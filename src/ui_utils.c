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
#include "config.h"
#endif
#include <pwd.h>

#include "appdata.h"
#include "ui_utils.h"
#include <pcap.h> /*JTC*/

/*

  Helper functions

*/

/* registers the named glade widget on the specified object */
void register_glade_widget(GtkBuilder *bldr, GtkWidget *tgt, const gchar *widgetName)
{
  GtkWidget *widget;
  widget = GTK_WIDGET(gtk_builder_get_object(bldr, widgetName));
  g_assert(widget);
  g_object_set_data(G_OBJECT(tgt), widgetName, widget);
}

void update_gtklabel(GtkWidget *window, const gchar *lblname, const gchar *value)
{
  GtkLabel *lbl = GTK_LABEL(g_object_get_data(G_OBJECT(window), lblname));
  gint start, end;
  gboolean sel = gtk_label_get_selection_bounds(lbl, &start, &end);
  gtk_label_set_text(lbl, value);
  if (sel)
    gtk_label_select_region(lbl, start, end);
}


void show_widget(GtkWidget *window, const gchar *lblname)
{
  GtkWidget *widget = g_object_get_data(G_OBJECT(window), lblname);
  gtk_widget_show(widget);
}
void hide_widget(GtkWidget *window, const gchar *lblname)
{
  GtkWidget *widget = g_object_get_data(G_OBJECT(window), lblname);
  gtk_widget_hide(widget);
}


/* creates a new text column with a specific title, column number colno and
 * adds it to treeview gv.  If r_just true the column is right justified */
void create_add_text_column(GtkTreeView *gv, const gchar *title, int colno,
                            gboolean r_just)
{
  GtkTreeViewColumn *gc;
  GtkCellRenderer *gr;

  gr = gtk_cell_renderer_text_new();
  if (r_just)
    g_object_set(G_OBJECT(gr), "xalign", 1.0, NULL);

  gc = gtk_tree_view_column_new_with_attributes(title, gr, "text", colno, NULL);
  g_object_set(G_OBJECT(gc), "resizable", TRUE,
               "reorderable", TRUE,
               NULL);
  gtk_tree_view_column_set_sort_column_id(gc, colno);
  gtk_tree_view_append_column(gv, gc);
}

/* returns a newly allocated string with a formatted traffic  */
gchar *traffic_to_str(gdouble traffic, gboolean is_speed)
{
  gchar *str;
  if (is_speed) {
    if (traffic > 1000000000.0)
      str = g_strdup_printf("%.2f Gbps", traffic / 1000000000.0);
    else if (traffic > 1000000)
      str = g_strdup_printf("%.2f Mbps", traffic / 1000000);
    else if (traffic > 1000)
      str = g_strdup_printf("%.2f Kbps", traffic / 1000);
    else
      str = g_strdup_printf("%.0f bps", traffic);
  }
  else {
    /* Debug code for sanity check */
    if (traffic && traffic < 1)
      g_warning("Ill traffic value in traffic_to_str");

    if (traffic > 1024.0 * 1024.0 * 1024.0)
      str = g_strdup_printf("%.2f Gbytes", traffic / (1024.0*1024.0*1024.0));
    else if (traffic > 1024 * 1024)
      str = g_strdup_printf("%.2f Mbytes", traffic / 1024 / 1024);
    else if (traffic > 1024)
      str = g_strdup_printf("%.2f Kbytes", traffic / 1024);
    else
      str = g_strdup_printf("%.0f bytes", traffic);
  }

  return str;
}                               /* traffic_to_str */

/* register/get a treeview to/from a window */
void register_treeview(GtkWidget *window, GtkTreeView *gv)
{
  g_assert(window);
  g_object_set_data(G_OBJECT(window), "EA_gv", gv);
}
GtkTreeView *retrieve_treeview(GtkWidget *window)
{
  if (!window)
    return NULL;
  return GTK_TREE_VIEW(g_object_get_data(G_OBJECT(window), "EA_gv"));
}

const char *get_home_dir(void)
{
  char *env_value;
  static const char *home = NULL;
  struct passwd *pwd;

  /* Return the cached value, if available */
  if (home)
    return home;

  env_value = getenv("HOME");

  if (env_value) {
    home = env_value;
  }
  else {
    pwd = getpwuid(getuid());
    if (pwd != NULL) {
      /* This is cached, so we don't need to worry
         about allocating multiple ones of them. */
      home = g_strdup(pwd->pw_dir);
    }
    else
      home = "/tmp";
  }

  return home;
}
