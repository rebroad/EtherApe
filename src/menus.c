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

#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>
#include "menus.h"
#include "ui_utils.h"
#include "diagram.h"
#include "stats/decode_proto.h"
#include "info_windows.h"
#include "capture/capctl.h"
#include "preferences.h"
#include "export.h"


static gboolean in_start_capture = FALSE;

static void set_active_interface(void);

void init_menus(void)
{
  GtkWidget *widget = NULL, *item = NULL;
  GList *interfaces;
  GList *iface;
  GSList *group = NULL;
  GString *info_string = NULL;
  GString *err_str = g_string_new("");

  interfaces = get_capture_interfaces(err_str);
  if (err_str)
    g_my_info(_("get_interface result: '%s'"), err_str->str);
  if (!interfaces) {
    g_my_info(_("No suitables interfaces for capture have been found"));
    if (err_str)
      g_string_free(err_str, TRUE);
    return;
  }
  if (err_str)
    g_string_free(err_str, TRUE);

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "interfaces_menu"));

  info_string = g_string_new(_("Available interfaces for capture:"));

  /* Set up a hidden dummy interface to set when there is no active
   * interface */
  item = gtk_radio_menu_item_new_with_label(group, "apedummy");
  group = gtk_radio_menu_item_get_group(GTK_RADIO_MENU_ITEM(item));
  gtk_menu_shell_append(GTK_MENU_SHELL(widget), item);

  /* Set up the real interfaces menu entries */
  for (iface = interfaces; iface; iface = iface->next) {
    item = gtk_radio_menu_item_new_with_label(group,
                                              (gchar *)(iface->data));
    group = gtk_radio_menu_item_get_group(GTK_RADIO_MENU_ITEM(item));
    gtk_menu_shell_append(GTK_MENU_SHELL(widget), item);
    gtk_widget_show(item);
    g_signal_connect_swapped(G_OBJECT(item), "activate",
                             G_CALLBACK(on_interface_radio_activate),
                             (gpointer)g_strdup(iface->data));
    g_string_append(info_string, " ");
    g_string_append(info_string, (gchar *)(iface->data));
  }

  if (info_string) {
    g_my_info("%s", info_string->str);
    g_string_free(info_string, TRUE);
  }

  free_capture_interfaces(interfaces);
}

/* FILE MENU */

void on_open_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  GtkWidget *dialog;

  if (!gui_stop_capture())
    return;

  dialog = gtk_file_chooser_dialog_new(_("Open Capture File"),
                                       NULL,
                                       GTK_FILE_CHOOSER_ACTION_OPEN,
                                       _("_Cancel"), GTK_RESPONSE_CANCEL,
                                       _("_Open"), GTK_RESPONSE_ACCEPT,
                                       NULL);
  if (appdata.source.type == ST_FILE && appdata.source.file)
    gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(dialog), appdata.source.file);

  if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
    GtkRecentManager *manager;
    manager = gtk_recent_manager_get_default();
    gtk_recent_manager_add_item(manager, gtk_file_chooser_get_uri(GTK_FILE_CHOOSER(dialog)));

    appdata_clear_source(&appdata);
    appdata.source.type = ST_FILE;
    appdata.source.file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    gtk_widget_destroy(dialog);

    gui_start_capture();
  }
  else
    gtk_widget_destroy(dialog);
}

void on_export_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  GtkWidget *dialog;

  dialog = gtk_file_chooser_dialog_new(_("Export to XML File"),
                                       NULL,
                                       GTK_FILE_CHOOSER_ACTION_SAVE,
                                       _("_Cancel"), GTK_RESPONSE_CANCEL,
                                       _("_Save"), GTK_RESPONSE_ACCEPT,
                                       NULL);
  gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);

  if (appdata.export_file)
    gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(dialog), appdata.export_file);

  if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
    GtkRecentManager *manager;
    manager = gtk_recent_manager_get_default();
    gtk_recent_manager_add_item(manager, gtk_file_chooser_get_uri(GTK_FILE_CHOOSER(dialog)));

    g_free(appdata.export_file);
    appdata.export_file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    gtk_widget_destroy(dialog);

    dump_xml(appdata.export_file);
  }
  else
    gtk_widget_destroy(dialog);
}

/* Capture menu */

void on_interface_radio_activate(gchar *gui_device)
{
  g_assert(gui_device != NULL);

  if (appdata.source.type == ST_LIVE && appdata.source.interface &&
      !strcmp(gui_device, appdata.source.interface))
    return;

  if (in_start_capture)
    return; /* Disregard when called because
                                 * of interface look change from
                                 * start_capture */

  if (!gui_stop_capture())
    return;

  appdata_clear_source(&appdata);
  appdata.source.type = ST_LIVE;
  appdata.source.interface = g_strdup(gui_device);

  gui_start_capture();

  g_my_info(_("Capture interface set to %s in GUI"), gui_device);
}

void on_mode_radio_activate(GtkRadioMenuItem *menuitem, gpointer user_data)
{
  apemode_t new_mode = APEMODE_DEFAULT;
  const gchar *menuname = NULL;
  gchar *filter;

  if (in_start_capture)
    return; /* Disregard when called because
                                 * of interface look change from
                                 * start_capture */

  menuname = gtk_widget_get_name(GTK_WIDGET(menuitem));
  g_assert(menuname);
  g_my_debug("Initial mode in on_mode_radio_activate %s",
             (gchar *)menuname);

  if (!strcmp("link_radio", menuname))
    new_mode = LINK6;
  else if (!strcmp("ip_radio", menuname))
    new_mode = IP;
  else if (!strcmp("tcp_radio", menuname))
    new_mode = TCP;
  else {
    g_my_critical(_("Unsupported mode in on_mode_radio_activate"));
    exit(1);
  }

  if (new_mode == appdata.mode)
    return;

  /* I don't know why, but this menu item is called twice, instead
   * of once. This forces me to make sure we are not trying to set
   * anything impossible */

  g_my_debug("Mode menuitem active: %d",
             gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem)));

  if (!has_linklevel() && new_mode == LINK6)
    return;

  if (!gui_stop_capture())
    return;

  /* if old filter was still default, we can change to default of new mode */
  filter = get_default_filter(appdata.mode);
  if (!strcmp(pref.filter, filter)) {
    g_free(pref.filter);
    pref.filter = get_default_filter(new_mode);
  }
  appdata.mode = new_mode;
  g_my_info(_("Mode set to %s in GUI"), (gchar *)menuitem);
  gui_start_capture();
}                               /* on_mode_radio_activate */

void on_start_menuitem_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  g_my_debug("on_start_menuitem_activate called");
  gui_start_capture();
}                               /* on_start_menuitem_activate */

void on_pause_menuitem_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  g_my_debug("on_pause_menuitem_activate called");
  gui_pause_capture();
}                               /* on_pause_menuitem_activate */

void on_next_menuitem_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  g_my_debug("on_next_menuitem_activate called");
  force_next_packet();
}

void on_stop_menuitem_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  g_my_debug("on_stop_menuitem_activate called");
  gui_stop_capture();
}                               /* on_stop_menuitem_activate */



/* View menu */

void on_full_screen_activate(GtkCheckMenuItem *menuitem, gpointer user_data)
{
  if (gtk_check_menu_item_get_active(menuitem))
    gtk_window_fullscreen((GtkWindow *)appdata.app1);
  else
    gtk_window_unfullscreen((GtkWindow *)appdata.app1);
}

void edit_prefs_show_toolbar(struct pref_struct *p, void *data)
{
  p->show_toolbar = *(gboolean *)data;
}

void on_toolbar_check_activate(GtkCheckMenuItem *menuitem, gpointer user_data)
{
  GtkWidget *widget;
  gboolean active = gtk_check_menu_item_get_active(menuitem);

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "toolbar"));
  if (active)
    gtk_widget_show(widget);
  else
    gtk_widget_hide(widget);

  pref.show_toolbar = active;
  mutate_saved_config(edit_prefs_show_toolbar, &active);
}

void edit_prefs_show_legend(struct pref_struct *p, void *data)
{
  p->show_legend = *(gboolean *)data;
}

void on_legend_check_activate(GtkCheckMenuItem *menuitem, gpointer user_data)
{
  GtkWidget *widget;
  gboolean active = gtk_check_menu_item_get_active(menuitem);

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "legend_frame"));
  if (active)
    gtk_widget_show(widget);
  else
    gtk_widget_hide(widget);

  pref.show_legend = active;
  mutate_saved_config(edit_prefs_show_legend, &active);
}

void edit_prefs_show_statusbar(struct pref_struct *p, void *data)
{
  p->show_statusbar = *(gboolean *)data;
}

void on_status_bar_check_activate(GtkCheckMenuItem *menuitem, gpointer user_data)
{
  gboolean active = gtk_check_menu_item_get_active(menuitem);

  if (active)
    gtk_widget_show(GTK_WIDGET(appdata.statusbar));
  else
    gtk_widget_hide(GTK_WIDGET(appdata.statusbar));

  pref.show_statusbar = active;
  mutate_saved_config(edit_prefs_show_statusbar, &active);
}


/* Help menu */



void on_about1_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  GtkWidget *about;
  about = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "about1"));

  gtk_about_dialog_set_version(GTK_ABOUT_DIALOG(about), VERSION);
#ifdef PACKAGE_SCM_REV
  msg = g_strdup_printf("HG revision: %s",
                        (*PACKAGE_SCM_REV) ? PACKAGE_SCM_REV : _("-unknown-"));
  gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG(about), msg);
  g_free(msg);
#endif
  gtk_widget_show(about);
}                               /* on_about1_activate */


void on_help_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  GError *err = NULL;
#if GTK_CHECK_VERSION(3, 22, 0)
  gtk_show_uri_on_window(NULL, "help:" PACKAGE_NAME, GDK_CURRENT_TIME, &err);
#else
  gtk_show_uri(NULL, "help:" PACKAGE_NAME, GDK_CURRENT_TIME, &err);
#endif
}

/* Helper functions */

#define EN_PLAY   1
#define EN_PAUSE  2
#define EN_NEXT   4
#define EN_STOP   8

static inline void set_widget_enabled_by_id(const gchar *id, gboolean onoff)
{
  GtkWidget *w = GTK_WIDGET(gtk_builder_get_object(appdata.xml, id));
  gtk_widget_set_sensitive(w, onoff);
}

static void set_ctrl_enablestate(guint32 flags)
{
  set_widget_enabled_by_id("start_button", !!(flags & EN_PLAY));
  set_widget_enabled_by_id("start_menuitem", !!(flags & EN_PLAY));
  set_widget_enabled_by_id("pause_button", !!(flags & EN_PAUSE));
  set_widget_enabled_by_id("pause_menuitem", !!(flags & EN_PAUSE));
  set_widget_enabled_by_id("next_button", !!(flags & EN_NEXT));
  set_widget_enabled_by_id("next_menuitem", !!(flags & EN_NEXT));
  set_widget_enabled_by_id("stop_button", !!(flags & EN_STOP));
  set_widget_enabled_by_id("stop_menuitem", !!(flags & EN_STOP));
}

/* Sets up the GUI to reflect changes and calls start_capture() */
void gui_start_capture(void)
{
  GtkWidget *widget;
  gchar *errorbuf = NULL;
  GString *status_string = NULL;

  if (get_capture_status() == CAP_EOF)
    if (!gui_stop_capture())
      return;



  if (get_capture_status() == STOP) {
    if ((errorbuf = start_capture()) != NULL) {
      fatal_error_dialog(errorbuf);
      return;
    }
  }
  else if (get_capture_status() == PLAY) {
    g_warning(_("Status already PLAY at gui_start_capture"));
    return;
  }
  else if (get_capture_status() == PAUSE) {
    errorbuf = unpause_capture();
    if (errorbuf) {
      fatal_error_dialog(errorbuf);
      return;
    }
  }

  in_start_capture = TRUE;

  /* Enable and disable control buttons */
  set_ctrl_enablestate(EN_STOP|EN_PAUSE|(appdata.source.type == ST_FILE ? EN_NEXT : 0));

  /* Enable and disable link layer menu */
  set_widget_enabled_by_id("link_radio", has_linklevel());

  /* Set active mode in GUI */
  switch (appdata.mode)
  {
      case LINK6:
        widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "link_radio"));
        break;
      case IP:
        widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "ip_radio"));
        break;
      case TCP:
        widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "tcp_radio"));
        break;
      default:
        g_warning(_("Invalid mode: %d"), appdata.mode);
        return;
  }
  gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), TRUE);

  /* Set the interface in GUI */
  set_active_interface();

  /* Sets the statusbar */
  status_string = g_string_new(_("Reading data from "));

  if (appdata.source.type == ST_FILE && appdata.source.file)
    g_string_append(status_string, appdata.source.file);
  else if (appdata.source.interface)
    g_string_append(status_string, appdata.source.interface);
  else
    g_string_append(status_string, _("default interface"));

  switch (appdata.mode)
  {
      case LINK6:
        g_string_append(status_string, _(" in Data Link mode"));
        break;
      case IP:
        g_string_append(status_string, _(" in IP mode"));
        break;
      case TCP:
        g_string_append(status_string, _(" in TCP mode"));
        break;
      default:
        g_critical(_("Invalid mode: %d"), appdata.mode);
        return;
  }

  set_statusbar_msg(status_string->str);
  g_string_free(status_string, TRUE);

  in_start_capture = FALSE;

  g_my_info(_("Diagram started"));
}                               /* gui_start_capture */

void gui_pause_capture(void)
{
  gchar *err;

  /*
   * Make sure the data in the info windows is updated
   * so that it is consistent
   */
  update_info_windows(NULL);

  err = pause_capture();
  if (err) {
    g_error("Error pausing capture: %s", err);
    g_free(err);
    return;
  }

  set_ctrl_enablestate(EN_PLAY|EN_STOP);

  set_statusbar_msg(_("Paused"));

  g_my_info(_("Diagram paused"));
  dump_stats(0);
}                               /* gui_pause_capture */

/* reached eof on a file replay */
void gui_eof_capture(void)
{
  GString *status_string = NULL;

  if (get_capture_status() == STOP)
    return;

  set_ctrl_enablestate(EN_PLAY);

  /* Sets the statusbar */
  status_string = g_string_new("");
  g_string_printf(status_string, _("Replay from file '%s' completed."), appdata.source.file);
  set_statusbar_msg(status_string->str);
  g_string_free(status_string, TRUE);
}                               /* gui_stop_capture */


/* Sets up the GUI to reflect changes and calls stop_capture() */
gboolean gui_stop_capture(void)
{
  GString *status_string = NULL;
  gchar *err;

  stop_requested = FALSE;
  if (get_capture_status() == STOP)
    return TRUE;

  /*
   * gui_stop_capture needs to call update_diagram in order to
   * delete all canvas_nodes and nodes. But since a slow running
   * update_diagram will yield to pending events, gui_stop_capture
   * might end up being called below another update_diagram. We can't
   * allow two simultaneous calls, so we fail
   */
  if (already_updating) {
    stop_requested = TRUE;
    return FALSE;
  }

  err = stop_capture();
  if (err) {
    g_error(_("Failed to stop capture: %s"), err);
    g_free(err);
    return FALSE;
  }

  set_ctrl_enablestate(EN_PLAY);

  /* Delete and free protocol information */
  delete_gui_protocols();

  /* final diagram update */
  update_diagram_callback(NULL);

  /* Sets the statusbar */
  status_string = g_string_new(_("Ready to capture from "));

  if (appdata.source.type == ST_FILE && appdata.source.file)
    g_string_append(status_string, appdata.source.file);
  else if (appdata.source.interface)
    g_string_append(status_string, appdata.source.interface);
  else
    g_string_append(status_string, _("default interface"));

  set_statusbar_msg(status_string->str);
  g_string_free(status_string, TRUE);

  g_my_info(_("Diagram stopped"));
  dump_stats(0);
  return TRUE;
}                               /* gui_stop_capture */

void fatal_error_dialog(const gchar *message)
{
  GtkWidget *error_messagebox;

  error_messagebox = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
                                            GTK_MESSAGE_ERROR,
                                            GTK_BUTTONS_OK, "%s", message);
  gtk_dialog_run(GTK_DIALOG(error_messagebox));
  gtk_widget_destroy(error_messagebox);
}

void setmenus(GtkWidget *widget, gpointer data)
{
  const gchar *label;

  if (appdata.source.type == ST_FILE) {
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), TRUE);
    return;
  }

  label = gtk_label_get_text(GTK_LABEL(gtk_bin_get_child(GTK_BIN(widget))));

  if (appdata.source.type == ST_LIVE && !strcmp(label, appdata.source.interface))
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), TRUE);
}

void set_active_interface()
{
  GtkWidget *widget;

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "interfaces_menu"));
  gtk_container_foreach(GTK_CONTAINER(widget), setmenus, (gpointer)NULL);
}

