
/*
 * DO NOT EDIT THIS FILE - it is generated by Glade.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
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
  GNOMEUIINFO_MENU_NEW_ITEM (N_ ("._New File"), NULL, on_new_file1_activate, NULL),
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

GtkWidget *
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
  GtkObject *averaging_spin_adj;
  GtkWidget *averaging_spin;
  GtkWidget *label6;
  GtkWidget *vbox4;
  GtkObject *refresh_spin_adj;
  GtkWidget *refresh_spin;
  GtkWidget *label7;
  GtkWidget *vbox5;
  GtkWidget *node_radius_slider;
  GtkWidget *label8;
  GtkWidget *vbox6;
  GtkWidget *link_width_slider;
  GtkWidget *label9;
  GtkWidget *vbox7;
  GtkObject *node_to_spin_adj;
  GtkWidget *node_to_spin;
  GtkWidget *label24;
  GtkWidget *vbox8;
  GtkObject *link_to_spin_adj;
  GtkWidget *link_to_spin;
  GtkWidget *label25;
  GtkWidget *frame3;
  GtkWidget *prot_table;
  GtkWidget *appbar1;

  app1 = gnome_app_new ("Etherape", _ ("Etherape"));
  gtk_object_set_data (GTK_OBJECT (app1), "app1", app1);
  gtk_window_set_default_size (GTK_WINDOW (app1), 780, 560);

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
					_ ("New"),
					_ ("Nuevo archivo"), NULL,
					tmp_toolbar_icon, NULL, NULL);
  gtk_widget_ref (button1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "button1", button1,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (button1);

  tmp_toolbar_icon = gnome_stock_pixmap_widget (app1, GNOME_STOCK_PIXMAP_OPEN);
  button2 = gtk_toolbar_append_element (GTK_TOOLBAR (toolbar1),
					GTK_TOOLBAR_CHILD_BUTTON,
					NULL,
					_ ("Open"),
					_ ("Abrir archivo"), NULL,
					tmp_toolbar_icon, NULL, NULL);
  gtk_widget_ref (button2);
  gtk_object_set_data_full (GTK_OBJECT (app1), "button2", button2,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (button2);

  tmp_toolbar_icon = gnome_stock_pixmap_widget (app1, GNOME_STOCK_PIXMAP_SAVE);
  button3 = gtk_toolbar_append_element (GTK_TOOLBAR (toolbar1),
					GTK_TOOLBAR_CHILD_BUTTON,
					NULL,
					_ ("Save"),
					_ ("Guardar archivo"), NULL,
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

  frame1 = gtk_frame_new (_ ("Diagram settings"));
  gtk_widget_ref (frame1);
  gtk_object_set_data_full (GTK_OBJECT (app1), "frame1", frame1,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (frame1);
  gtk_box_pack_start (GTK_BOX (vbox1), frame1, FALSE, TRUE, 0);

  vbox2 = gtk_vbox_new (FALSE, 10);
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
  gtk_box_pack_start (GTK_BOX (vbox2), vbox3, FALSE, FALSE, 2);

  averaging_spin_adj = gtk_adjustment_new (10000, 1, 3.6e+07, 100, 1000, 10000);
  averaging_spin = gtk_spin_button_new (GTK_ADJUSTMENT (averaging_spin_adj), 1, 0);
  gtk_widget_ref (averaging_spin);
  gtk_object_set_data_full (GTK_OBJECT (app1), "averaging_spin", averaging_spin,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (averaging_spin);
  gtk_box_pack_start (GTK_BOX (vbox3), averaging_spin, FALSE, FALSE, 0);
  gtk_spin_button_set_update_policy (GTK_SPIN_BUTTON (averaging_spin), GTK_UPDATE_IF_VALID);

  label6 = gtk_label_new (_ ("Averaging Time (ms)"));
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
  gtk_box_pack_start (GTK_BOX (vbox2), vbox4, FALSE, FALSE, 0);

  refresh_spin_adj = gtk_adjustment_new (800, 50, 10000, 10, 100, 100);
  refresh_spin = gtk_spin_button_new (GTK_ADJUSTMENT (refresh_spin_adj), 1, 0);
  gtk_widget_ref (refresh_spin);
  gtk_object_set_data_full (GTK_OBJECT (app1), "refresh_spin", refresh_spin,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (refresh_spin);
  gtk_box_pack_start (GTK_BOX (vbox4), refresh_spin, FALSE, FALSE, 2);

  label7 = gtk_label_new (_ ("Diagram refresh period (ms)"));
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
  gtk_box_pack_start (GTK_BOX (vbox2), vbox5, FALSE, FALSE, 0);

  node_radius_slider = gtk_hscale_new (GTK_ADJUSTMENT (gtk_adjustment_new (3, 0, 5, 0.25, 1, 0)));
  gtk_widget_ref (node_radius_slider);
  gtk_object_set_data_full (GTK_OBJECT (app1), "node_radius_slider", node_radius_slider,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (node_radius_slider);
  gtk_box_pack_start (GTK_BOX (vbox5), node_radius_slider, FALSE, FALSE, 2);
  gtk_scale_set_draw_value (GTK_SCALE (node_radius_slider), FALSE);
  gtk_range_set_update_policy (GTK_RANGE (node_radius_slider), GTK_UPDATE_DISCONTINUOUS);

  label8 = gtk_label_new (_ ("Max. Node Radius"));
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
  gtk_box_pack_start (GTK_BOX (vbox2), vbox6, FALSE, FALSE, 0);

  link_width_slider = gtk_hscale_new (GTK_ADJUSTMENT (gtk_adjustment_new (3, 0, 5, 0.25, 1, 0)));
  gtk_widget_ref (link_width_slider);
  gtk_object_set_data_full (GTK_OBJECT (app1), "link_width_slider", link_width_slider,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (link_width_slider);
  gtk_box_pack_start (GTK_BOX (vbox6), link_width_slider, FALSE, FALSE, 2);
  gtk_scale_set_draw_value (GTK_SCALE (link_width_slider), FALSE);
  gtk_range_set_update_policy (GTK_RANGE (link_width_slider), GTK_UPDATE_DISCONTINUOUS);

  label9 = gtk_label_new (_ ("Max. Link Width"));
  gtk_widget_ref (label9);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label9", label9,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label9);
  gtk_box_pack_start (GTK_BOX (vbox6), label9, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label9), GTK_JUSTIFY_LEFT);

  vbox7 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox7);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox7", vbox7,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox7);
  gtk_box_pack_start (GTK_BOX (vbox2), vbox7, TRUE, TRUE, 0);

  node_to_spin_adj = gtk_adjustment_new (10000, 0, 3.6e+07, 100, 1000, 10000);
  node_to_spin = gtk_spin_button_new (GTK_ADJUSTMENT (node_to_spin_adj), 1, 0);
  gtk_widget_ref (node_to_spin);
  gtk_object_set_data_full (GTK_OBJECT (app1), "node_to_spin", node_to_spin,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (node_to_spin);
  gtk_box_pack_start (GTK_BOX (vbox7), node_to_spin, FALSE, FALSE, 0);
  gtk_spin_button_set_update_policy (GTK_SPIN_BUTTON (node_to_spin), GTK_UPDATE_IF_VALID);

  label24 = gtk_label_new (_ ("Node Timeout (ms)"));
  gtk_widget_ref (label24);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label24", label24,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label24);
  gtk_box_pack_start (GTK_BOX (vbox7), label24, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label24), GTK_JUSTIFY_LEFT);

  vbox8 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox8);
  gtk_object_set_data_full (GTK_OBJECT (app1), "vbox8", vbox8,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox8);
  gtk_box_pack_start (GTK_BOX (vbox2), vbox8, TRUE, TRUE, 0);

  link_to_spin_adj = gtk_adjustment_new (2000, 0, 3.6e+07, 100, 1000, 10000);
  link_to_spin = gtk_spin_button_new (GTK_ADJUSTMENT (link_to_spin_adj), 1, 0);
  gtk_widget_ref (link_to_spin);
  gtk_object_set_data_full (GTK_OBJECT (app1), "link_to_spin", link_to_spin,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (link_to_spin);
  gtk_box_pack_start (GTK_BOX (vbox8), link_to_spin, FALSE, FALSE, 0);
  gtk_spin_button_set_update_policy (GTK_SPIN_BUTTON (link_to_spin), GTK_UPDATE_IF_VALID);

  label25 = gtk_label_new (_ ("Link Timeout (ms)"));
  gtk_widget_ref (label25);
  gtk_object_set_data_full (GTK_OBJECT (app1), "label25", label25,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label25);
  gtk_box_pack_start (GTK_BOX (vbox8), label25, FALSE, FALSE, 0);
  gtk_label_set_justify (GTK_LABEL (label25), GTK_JUSTIFY_LEFT);

  frame3 = gtk_frame_new (_ ("Protocols"));
  gtk_widget_ref (frame3);
  gtk_object_set_data_full (GTK_OBJECT (app1), "frame3", frame3,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (frame3);
  gtk_box_pack_start (GTK_BOX (vbox1), frame3, TRUE, TRUE, 0);

  prot_table = gtk_table_new (1, 1, TRUE);
  gtk_widget_ref (prot_table);
  gtk_object_set_data_full (GTK_OBJECT (app1), "prot_table", prot_table,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (prot_table);
  gtk_container_add (GTK_CONTAINER (frame3), prot_table);

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

GtkWidget *
create_about2 (void)
{
  const gchar *authors[] =
  {
    "Juan Toledo <toledo@users.sourceforge.net>",
    "Laurent Deniel <deniel@worldnet.fr>",
    "Simon Kirby <sim@neato.org>",
    "Jasper Wallace <jasper@pointless.net>",
    "Ted Wright <ted.wright@grc.nasa.gov>",
    NULL
  };
  GtkWidget *about2;

  about2 = gnome_about_new ("Etherape", VERSION,
			    _ ("Copyright 2000 Juan Toledo"),
			    authors,
   _ ("A Graphical Network Browser.\nWeb: http://etherape.sourceforge.net"),
			    NULL);
  gtk_object_set_data (GTK_OBJECT (about2), "about2", about2);
  gtk_window_set_modal (GTK_WINDOW (about2), TRUE);

  return about2;
}

GtkWidget *
create_node_popup (void)
{
  GtkWidget *node_popup;
  GtkWidget *frame2;
  GtkWidget *table1;
  GtkWidget *name;
  GtkWidget *accumulated;
  GtkWidget *average;

  node_popup = gtk_window_new (GTK_WINDOW_POPUP);
  gtk_object_set_data (GTK_OBJECT (node_popup), "node_popup", node_popup);
  gtk_window_set_title (GTK_WINDOW (node_popup), _ ("window1"));
  gtk_window_set_position (GTK_WINDOW (node_popup), GTK_WIN_POS_MOUSE);
  gtk_window_set_policy (GTK_WINDOW (node_popup), FALSE, FALSE, TRUE);

  frame2 = gtk_frame_new (NULL);
  gtk_widget_ref (frame2);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "frame2", frame2,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (frame2);
  gtk_container_add (GTK_CONTAINER (node_popup), frame2);

  table1 = gtk_table_new (3, 1, TRUE);
  gtk_widget_ref (table1);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "table1", table1,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (table1);
  gtk_container_add (GTK_CONTAINER (frame2), table1);
  gtk_container_set_border_width (GTK_CONTAINER (table1), 3);
  gtk_table_set_col_spacings (GTK_TABLE (table1), 5);

  name = gtk_label_new (_ ("name"));
  gtk_widget_ref (name);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "name", name,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (name);
  gtk_table_attach (GTK_TABLE (table1), name, 0, 1, 0, 1,
		    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		    (GtkAttachOptions) (GTK_EXPAND), 0, 0);

  accumulated = gtk_label_new (_ ("accumulated"));
  gtk_widget_ref (accumulated);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "accumulated", accumulated,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (accumulated);
  gtk_table_attach (GTK_TABLE (table1), accumulated, 0, 1, 1, 2,
		    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		    (GtkAttachOptions) (GTK_EXPAND), 0, 0);

  average = gtk_label_new (_ ("average"));
  gtk_widget_ref (average);
  gtk_object_set_data_full (GTK_OBJECT (node_popup), "average", average,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (average);
  gtk_table_attach (GTK_TABLE (table1), average, 0, 1, 2, 3,
		    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		    (GtkAttachOptions) (GTK_EXPAND), 0, 0);

  gtk_signal_connect (GTK_OBJECT (node_popup), "motion_notify_event",
		      GTK_SIGNAL_FUNC (gtk_widget_destroy),
		      NULL);

  return node_popup;
}

GtkWidget *
create_messagebox1 (void)
{
  GtkWidget *messagebox1;
  GtkWidget *dialog_vbox1;
  GtkWidget *button4;
  GtkWidget *dialog_action_area1;

  messagebox1 = gnome_message_box_new (_ ("This message is not here yet. (Don�t tell anybody you saw it ;-) )"),
				       GNOME_MESSAGE_BOX_QUESTION, NULL);
  gtk_object_set_data (GTK_OBJECT (messagebox1), "messagebox1", messagebox1);
  gtk_window_set_modal (GTK_WINDOW (messagebox1), TRUE);
  gtk_window_set_policy (GTK_WINDOW (messagebox1), FALSE, FALSE, FALSE);
  gnome_dialog_set_close (GNOME_DIALOG (messagebox1), TRUE);

  dialog_vbox1 = GNOME_DIALOG (messagebox1)->vbox;
  gtk_object_set_data (GTK_OBJECT (messagebox1), "dialog_vbox1", dialog_vbox1);
  gtk_widget_show (dialog_vbox1);

  gnome_dialog_append_button (GNOME_DIALOG (messagebox1), GNOME_STOCK_BUTTON_OK);
  button4 = g_list_last (GNOME_DIALOG (messagebox1)->buttons)->data;
  gtk_widget_ref (button4);
  gtk_object_set_data_full (GTK_OBJECT (messagebox1), "button4", button4,
			    (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (button4);
  GTK_WIDGET_SET_FLAGS (button4, GTK_CAN_DEFAULT);

  dialog_action_area1 = GNOME_DIALOG (messagebox1)->action_area;
  gtk_widget_ref (dialog_action_area1);
  gtk_object_set_data_full (GTK_OBJECT (messagebox1), "dialog_action_area1", dialog_action_area1,
			    (GtkDestroyNotify) gtk_widget_unref);

  return messagebox1;
}
