/*
 * DO NOT EDIT THIS FILE - it is generated by Glade.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <gnome.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"

static GnomeUIInfo file1_menu_uiinfo[] =
{
  GNOMEUIINFO_MENU_NEW_ITEM (N_("._New File"), NULL, on_new_file1_activate, NULL),
  GNOMEUIINFO_MENU_OPEN_ITEM (on_open1_activate, NULL),
  GNOMEUIINFO_MENU_SAVE_ITEM (on_save1_activate, NULL),
  GNOMEUIINFO_MENU_SAVE_AS_ITEM (on_save_as1_activate, NULL),
  GNOMEUIINFO_SEPARATOR,
  GNOMEUIINFO_MENU_EXIT_ITEM (on_exit1_activate, NULL),
  GNOMEUIINFO_END
};

static GnomeUIInfo edit1_menu_uiinfo[] =
{
  GNOMEUIINFO_MENU_CUT_ITEM (on_cut1_activate, NULL),
  GNOMEUIINFO_MENU_COPY_ITEM (on_copy1_activate, NULL),
  GNOMEUIINFO_MENU_PASTE_ITEM (on_paste1_activate, NULL),
  GNOMEUIINFO_MENU_CLEAR_ITEM (on_clear1_activate, NULL),
  GNOMEUIINFO_SEPARATOR,
  GNOMEUIINFO_MENU_PROPERTIES_ITEM (on_properties1_activate, NULL),
  GNOMEUIINFO_END
};

static GnomeUIInfo view1_menu_uiinfo[] =
{
  GNOMEUIINFO_END
};

static GnomeUIInfo settings1_menu_uiinfo[] =
{
  GNOMEUIINFO_MENU_PREFERENCES_ITEM (on_preferences1_activate, NULL),
  GNOMEUIINFO_END
};

static GnomeUIInfo help1_menu_uiinfo[] =
{
  GNOMEUIINFO_MENU_ABOUT_ITEM (on_about1_activate, NULL),
  GNOMEUIINFO_END
};

static GnomeUIInfo menubar1_uiinfo[] =
{
  GNOMEUIINFO_MENU_FILE_TREE (file1_menu_uiinfo),
  GNOMEUIINFO_MENU_EDIT_TREE (edit1_menu_uiinfo),
  GNOMEUIINFO_MENU_VIEW_TREE (view1_menu_uiinfo),
  GNOMEUIINFO_MENU_SETTINGS_TREE (settings1_menu_uiinfo),
  GNOMEUIINFO_MENU_HELP_TREE (help1_menu_uiinfo),
  GNOMEUIINFO_END
};

GtkWidget*
create_app1 (void)
{
  GtkWidget *app1;
  GtkWidget *dock1;
  GtkWidget *toolbar1;
  GtkWidget *tmp_toolbar_icon;
  GtkWidget *button1;
  GtkWidget *button2;
  GtkWidget *button3;
  GtkWidget *hpaned1;
  GtkWidget *scrolledwindow1;
  GtkWidget *canvas1;
  GtkWidget *vbox1;
  GtkWidget *frame1;
  GtkWidget *vbox2;
  GtkWidget *vbox3;
  GtkWidget *hscale4;
  GtkWidget *label6;
  GtkWidget *vbox4;
  GtkWidget *hscale5;
  GtkWidget *label7;
  GtkWidget *vbox5;
  GtkWidget *hscale6;
  GtkWidget *label8;
  GtkWidget *vbox6;
  GtkWidget *hscale7;
  GtkWidget *label9;
  GtkWidget *label10;
  GtkWidget *appbar1;

  app1 = gnome_app_new ("Etherape", _("Etherape"));
  gtk_object_set_data (GTK_OBJECT (app1), "app1", app1);
  gtk_window_set_default_size (GTK_WINDOW (app1), 800, 600);

  dock1 = GNOME_APP (app1)->dock;
  gtk_widget_ref (dock1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "dock1", dock1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (dock1);

  gnome_app_create_menus (GNOME_APP (app1), menubar1_uiinfo);

  gtk_widget_ref (menubar1_uiinfo[0].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "file1",
                            menubar1_uiinfo[0].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (file1_menu_uiinfo[0].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "new_file1",
                            file1_menu_uiinfo[0].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (file1_menu_uiinfo[1].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "open1",
                            file1_menu_uiinfo[1].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (file1_menu_uiinfo[2].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "save1",
                            file1_menu_uiinfo[2].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (file1_menu_uiinfo[3].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "save_as1",
                            file1_menu_uiinfo[3].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (file1_menu_uiinfo[4].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "separator1",
                            file1_menu_uiinfo[4].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (file1_menu_uiinfo[5].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "exit1",
                            file1_menu_uiinfo[5].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (menubar1_uiinfo[1].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "edit1",
                            menubar1_uiinfo[1].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (edit1_menu_uiinfo[0].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "cut1",
                            edit1_menu_uiinfo[0].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (edit1_menu_uiinfo[1].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "copy1",
                            edit1_menu_uiinfo[1].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (edit1_menu_uiinfo[2].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "paste1",
                            edit1_menu_uiinfo[2].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (edit1_menu_uiinfo[3].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "clear1",
                            edit1_menu_uiinfo[3].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (edit1_menu_uiinfo[4].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "separator2",
                            edit1_menu_uiinfo[4].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (edit1_menu_uiinfo[5].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "properties1",
                            edit1_menu_uiinfo[5].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (menubar1_uiinfo[2].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "view1",
                            menubar1_uiinfo[2].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (menubar1_uiinfo[3].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "settings1",
                            menubar1_uiinfo[3].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (settings1_menu_uiinfo[0].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "preferences1",
                            settings1_menu_uiinfo[0].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (menubar1_uiinfo[4].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "help1",
                            menubar1_uiinfo[4].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  gtk_widget_ref (help1_menu_uiinfo[0].widget);
  gtk_object_set_data_full (GTK_OBJECT (app1), "about1",
                            help1_menu_uiinfo[0].widget,
                            (GtkDestroyNotify) gtk_widget_unref);

  toolbar1 = gtk_toolbar_new (GTK_ORIENTATION_HORIZONTAL, GTK_TOOLBAR_BOTH);
  gtk_widget_ref (toolbar1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "toolbar1", toolbar1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (toolbar1);
  gnome_app_add_toolbar (GNOME_APP (app1), GTK_TOOLBAR (toolbar1), "toolbar1",
                                GNOME_DOCK_ITEM_BEH_EXCLUSIVE,
                                GNOME_DOCK_TOP, 1, 0, 0);
  gtk_container_set_border_width (GTK_CONTAINER (toolbar1), 1);
  gtk_toolbar_set_space_size (GTK_TOOLBAR (toolbar1), 16);
  gtk_toolbar_set_space_style (GTK_TOOLBAR (toolbar1), GTK_TOOLBAR_SPACE_LINE);
  gtk_toolbar_set_button_relief (GTK_TOOLBAR (toolbar1), GTK_RELIEF_NONE);

  tmp_toolbar_icon = gnome_stock_pixmap_widget (app1, GNOME_STOCK_PIXMAP_NEW);
  button1 = gtk_toolbar_append_element (GTK_TOOLBAR (toolbar1),
                                GTK_TOOLBAR_CHILD_BUTTON,
                                NULL,
                                _("New"),
                                _("Nuevo archivo"), NULL,
                                tmp_toolbar_icon, NULL, NULL);
  gtk_widget_ref (button1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "button1", button1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (button1);

  tmp_toolbar_icon = gnome_stock_pixmap_widget (app1, GNOME_STOCK_PIXMAP_OPEN);
  button2 = gtk_toolbar_append_element (GTK_TOOLBAR (toolbar1),
                                GTK_TOOLBAR_CHILD_BUTTON,
                                NULL,
                                _("Open"),
                                _("Abrir archivo"), NULL,
                                tmp_toolbar_icon, NULL, NULL);
  gtk_widget_ref (button2);
  gtk_object_set_data_full (GTK_OBJECT (app1), "button2", button2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (button2);

  tmp_toolbar_icon = gnome_stock_pixmap_widget (app1, GNOME_STOCK_PIXMAP_SAVE);
  button3 = gtk_toolbar_append_element (GTK_TOOLBAR (toolbar1),
                                GTK_TOOLBAR_CHILD_BUTTON,
                                NULL,
                                _("Save"),
                                _("Guardar archivo"), NULL,
                                tmp_toolbar_icon, NULL, NULL);
  gtk_widget_ref (button3);
  gtk_object_set_data_full (GTK_OBJECT (app1), "button3", button3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (button3);

  hpaned1 = gtk_hpaned_new ();
  gtk_widget_ref (hpaned1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "hpaned1", hpaned1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hpaned1);
  gnome_app_set_contents (GNOME_APP (app1), hpaned1);
  gtk_paned_set_position (GTK_PANED (hpaned1), 600);

  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "scrolledwindow1", scrolledwindow1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow1);
  gtk_container_add (GTK_CONTAINER (hpaned1), scrolledwindow1);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwindow1), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

  gtk_widget_push_visual (gdk_imlib_get_visual ());
  gtk_widget_push_colormap (gdk_imlib_get_colormap ());
  canvas1 = gnome_canvas_new ();
  gtk_widget_pop_colormap ();
  gtk_widget_pop_visual ();
  gtk_widget_ref (canvas1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "canvas1", canvas1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (canvas1);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), canvas1);
  gnome_canvas_set_scroll_region (GNOME_CANVAS (canvas1), -280, -200, 280, 200);

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox1", vbox1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (hpaned1), vbox1);

  frame1 = gtk_frame_new (_("Diagram settings"));
  gtk_widget_ref (frame1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "frame1", frame1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (frame1);
  gtk_box_pack_start (GTK_BOX (vbox1), frame1, FALSE, TRUE, 0);

  vbox2 = gtk_vbox_new (TRUE, 0);
  gtk_widget_ref (vbox2);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox2", vbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox2);
  gtk_container_add (GTK_CONTAINER (frame1), vbox2);

  vbox3 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox3);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox3", vbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox3);
  gtk_box_pack_start (GTK_BOX (vbox2), vbox3, FALSE, TRUE, 2);

  hscale4 = gtk_hscale_new (GTK_ADJUSTMENT (gtk_adjustment_new (0, 0, 0, 0, 0, 0)));
  gtk_widget_ref (hscale4);
  gtk_object_set_data_full (GTK_OBJECT (app1), "hscale4", hscale4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hscale4);
  gtk_box_pack_start (GTK_BOX (vbox3), hscale4, TRUE, TRUE, 0);
  gtk_scale_set_draw_value (GTK_SCALE (hscale4), FALSE);
  gtk_scale_set_value_pos (GTK_SCALE (hscale4), GTK_POS_RIGHT);

  label6 = gtk_label_new (_("Averaging Time"));
  gtk_widget_ref (label6);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label6", label6,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label6);
  gtk_box_pack_start (GTK_BOX (vbox3), label6, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label6), GTK_JUSTIFY_LEFT);

  vbox4 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox4);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox4", vbox4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox4);
  gtk_box_pack_start (GTK_BOX (vbox2), vbox4, FALSE, TRUE, 0);

  hscale5 = gtk_hscale_new (GTK_ADJUSTMENT (gtk_adjustment_new (0, 0, 0, 0, 0, 0)));
  gtk_widget_ref (hscale5);
  gtk_object_set_data_full (GTK_OBJECT (app1), "hscale5", hscale5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hscale5);
  gtk_box_pack_start (GTK_BOX (vbox4), hscale5, FALSE, TRUE, 2);
  gtk_scale_set_draw_value (GTK_SCALE (hscale5), FALSE);

  label7 = gtk_label_new (_("Diagram refresh period"));
  gtk_widget_ref (label7);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label7", label7,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label7);
  gtk_box_pack_start (GTK_BOX (vbox4), label7, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label7), GTK_JUSTIFY_LEFT);

  vbox5 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox5);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox5", vbox5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox5);
  gtk_box_pack_start (GTK_BOX (vbox2), vbox5, TRUE, TRUE, 0);

  hscale6 = gtk_hscale_new (GTK_ADJUSTMENT (gtk_adjustment_new (2.8, 0, 5, 0.25, 1, 0)));
  gtk_widget_ref (hscale6);
  gtk_object_set_data_full (GTK_OBJECT (app1), "hscale6", hscale6,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hscale6);
  gtk_box_pack_start (GTK_BOX (vbox5), hscale6, FALSE, TRUE, 2);
  gtk_scale_set_draw_value (GTK_SCALE (hscale6), FALSE);
  gtk_range_set_update_policy (GTK_RANGE (hscale6), GTK_UPDATE_DISCONTINUOUS);

  label8 = gtk_label_new (_("Max. Node Radius"));
  gtk_widget_ref (label8);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label8", label8,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label8);
  gtk_box_pack_start (GTK_BOX (vbox5), label8, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label8), GTK_JUSTIFY_LEFT);

  vbox6 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox6);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox6", vbox6,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox6);
  gtk_box_pack_start (GTK_BOX (vbox2), vbox6, FALSE, TRUE, 0);

  hscale7 = gtk_hscale_new (GTK_ADJUSTMENT (gtk_adjustment_new (0, 0, 0, 0, 0, 0)));
  gtk_widget_ref (hscale7);
  gtk_object_set_data_full (GTK_OBJECT (app1), "hscale7", hscale7,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hscale7);
  gtk_box_pack_start (GTK_BOX (vbox6), hscale7, FALSE, FALSE, 2);
  gtk_scale_set_draw_value (GTK_SCALE (hscale7), FALSE);

  label9 = gtk_label_new (_("Max Link Radius"));
  gtk_widget_ref (label9);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label9", label9,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label9);
  gtk_box_pack_start (GTK_BOX (vbox6), label9, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label9), GTK_JUSTIFY_LEFT);

  label10 = gtk_label_new (_("Place Holder for The Color Coded Protocols display"));
  gtk_widget_ref (label10);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label10", label10,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label10);
  gtk_box_pack_start (GTK_BOX (vbox1), label10, TRUE, FALSE, 0);
  gtk_label_set_line_wrap (GTK_LABEL (label10), TRUE);

  appbar1 = gnome_appbar_new (TRUE, TRUE, GNOME_PREFERENCES_NEVER);
  gtk_widget_ref (appbar1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "appbar1", appbar1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (appbar1);
  gnome_app_set_statusbar (GNOME_APP (app1), appbar1);

  gtk_signal_connect (GTK_OBJECT (app1), "delete_event",
                      GTK_SIGNAL_FUNC (on_app1_delete_event),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (canvas1), "size_allocate",
                      GTK_SIGNAL_FUNC (on_canvas1_size_allocate),
                      NULL);

  return app1;
}

GtkWidget*
create_about2 (void)
{
  const gchar *authors[] = {
    "Juan Toledo <toledo@users.sourceforge.net>",
    "Laurent Deniel <deniel@worldnet.fr>",
    "    -> Routines for network object lookup",
    "Jasper Wallace <jasper@pointless.net>",
    NULL
  };
  GtkWidget *about2;

  about2 = gnome_about_new ("Etherape", VERSION,
                        _("Copyright 2000 Juan Toledo"),
                        authors,
                        _("A Graphical Network Browser.\nWeb: http://etherape.sourceforge.net"),
                        NULL);
  gtk_object_set_data (GTK_OBJECT (about2), "about2", about2);
  gtk_window_set_modal (GTK_WINDOW (about2), TRUE);

  return about2;
}

GtkWidget*
create_node_popup (void)
{
  GtkWidget *node_popup;
  GtkWidget *table1;
  GtkWidget *node_name;
  GtkWidget *ether_address;
  GtkWidget *ip_address;

  node_popup = gtk_window_new (GTK_WINDOW_POPUP);
  gtk_object_set_data (GTK_OBJECT (node_popup), "node_popup", node_popup);
  gtk_window_set_title (GTK_WINDOW (node_popup), _("window1"));
  gtk_window_set_position (GTK_WINDOW (node_popup), GTK_WIN_POS_MOUSE);
  gtk_window_set_policy (GTK_WINDOW (node_popup), FALSE, FALSE, TRUE);

  table1 = gtk_table_new (3, 2, TRUE);
  gtk_widget_ref (table1);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "table1", table1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (table1);
  gtk_container_add (GTK_CONTAINER (node_popup), table1);

  node_name = gtk_label_new ("");
  gtk_label_parse_uline (GTK_LABEL (node_name),
                         _("node_name"));
  gtk_widget_ref (node_name);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "node_name", node_name,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (node_name);
  gtk_table_attach (GTK_TABLE (table1), node_name, 0, 1, 0, 1,
                    (GtkAttachOptions) (0),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (node_name), GTK_JUSTIFY_LEFT);

  ether_address = gtk_label_new ("");
  gtk_label_parse_uline (GTK_LABEL (ether_address),
                         _("ether_address"));
  gtk_widget_ref (ether_address);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "ether_address", ether_address,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (ether_address);
  gtk_table_attach (GTK_TABLE (table1), ether_address, 0, 1, 1, 2,
                    (GtkAttachOptions) (0),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (ether_address), GTK_JUSTIFY_LEFT);

  ip_address = gtk_label_new ("");
  gtk_label_parse_uline (GTK_LABEL (ip_address),
                         _("ip_address"));
  gtk_widget_ref (ip_address);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "ip_address", ip_address,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (ip_address);
  gtk_table_attach (GTK_TABLE (table1), ip_address, 0, 1, 2, 3,
                    (GtkAttachOptions) (0),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_label_set_justify (GTK_LABEL (ip_address), GTK_JUSTIFY_LEFT);

  return node_popup;
}

