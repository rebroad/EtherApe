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
#include "config.h"
#endif

#include <gtk/gtk.h>

#include "pref_dialog.h"
#include "preferences.h"
#include "diagram.h"
#include "capture/capctl.h"
#include "stats/node.h"
#include "datastructs.h"
#include "compat.h"

#define MILLI      (1000.0)
#define COLSPACES  "        "

static void color_list_to_pref(void);
static void pref_to_color_list(void);
static void on_stack_level_changed(GtkWidget *combo, gpointer data);
static void on_size_variable_changed(GtkComboBox *combo, gpointer data);
static void on_size_mode_changed(GtkComboBox *combo, gpointer data);
static void on_text_color_changed(GtkColorButton *wdg, gpointer data);
static void on_text_font_changed(GtkFontButton *wdg, gpointer data);
static void on_filter_entry_changed(GtkComboBox *cbox, gpointer user_data);
static void on_center_node_changed(GtkComboBox *cbox, gpointer user_data);
static void cbox_add_select(GtkComboBox *cbox, const gchar *str);


static gboolean colors_changed = FALSE;
static GtkWidget *diag_pref = NULL;  /* diagram configuration window */
static struct pref_struct tmp_pref; /* tmp copy of pref data */


static void confirm_changes(void)
{
  GtkWidget *widget = NULL;

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "filter_combo"));
  on_filter_entry_changed(GTK_COMBO_BOX(widget), NULL);

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "center_combo"));
  on_center_node_changed(GTK_COMBO_BOX(widget), NULL);

  if (colors_changed) {
    color_list_to_pref();
    delete_gui_protocols();
  }
}                               /* confirm_changes */

static void hide_pref_dialog(void)
{
  /* purge temporary */
  free_config(&tmp_pref);

  /* reset flags */
  colors_changed = FALSE;

  /* hide dialog */
  gtk_widget_hide(diag_pref);
}

void initialize_pref_controls(void)
{
  GtkWidget *widget;
  GtkSpinButton *spin;
  GdkRGBA color;
  GtkTreeModel *model;

  diag_pref = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "diag_pref"));

  /* Updates controls from values of variables */
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "node_radius_slider"));
  gtk_adjustment_set_value(gtk_range_get_adjustment(GTK_RANGE(widget)),
                           log(pref.node_radius_multiplier) / log(10));
  g_signal_emit_by_name(G_OBJECT(gtk_range_get_adjustment(GTK_RANGE(widget))),
                        "changed");
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "inner_ring_scale_slider"));
  gtk_adjustment_set_value(gtk_range_get_adjustment(GTK_RANGE(widget)),
                           pref.inner_ring_scale);
  g_signal_emit_by_name(G_OBJECT(gtk_range_get_adjustment(GTK_RANGE(widget))), "changed");
  spin = GTK_SPIN_BUTTON(gtk_builder_get_object(appdata.xml, "averaging_spin"));
  gtk_spin_button_set_value(spin, pref.averaging_time);
  spin = GTK_SPIN_BUTTON(gtk_builder_get_object(appdata.xml, "refresh_spin"));
  gtk_spin_button_set_value(spin, pref.refresh_period);
  spin = GTK_SPIN_BUTTON(gtk_builder_get_object(appdata.xml, "gui_node_to_spin"));
  gtk_spin_button_set_value(spin, pref.gui_node_timeout_time/MILLI);
  spin = GTK_SPIN_BUTTON(gtk_builder_get_object(appdata.xml, "proto_node_to_spin"));
  gtk_spin_button_set_value(spin, pref.proto_node_timeout_time/MILLI);

  spin = GTK_SPIN_BUTTON(gtk_builder_get_object(appdata.xml, "gui_link_to_spin"));
  gtk_spin_button_set_value(spin, pref.gui_link_timeout_time/MILLI);
  spin = GTK_SPIN_BUTTON(gtk_builder_get_object(appdata.xml, "proto_link_to_spin"));
  gtk_spin_button_set_value(spin, pref.proto_link_timeout_time/MILLI);

  spin = GTK_SPIN_BUTTON(gtk_builder_get_object(appdata.xml, "proto_to_spin"));
  gtk_spin_button_set_value(spin, pref.proto_timeout_time/MILLI);

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "diagram_only_toggle"));
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget),
                               pref.diagram_only);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "group_unk_check"));
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), pref.group_unk);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "name_res_check"));
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), pref.name_res);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "stack_level"));
  gtk_combo_box_set_active(GTK_COMBO_BOX(widget), pref.stack_level);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "size_variable"));
  gtk_combo_box_set_active(GTK_COMBO_BOX(widget), pref.node_size_variable);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "size_mode"));
  gtk_combo_box_set_active(GTK_COMBO_BOX(widget), pref.size_mode);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "text_font"));
  gtk_font_button_set_font_name(GTK_FONT_BUTTON(widget), pref.fontname);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "text_color"));
  if (!gdk_rgba_parse(&color, pref.text_color))
    gdk_rgba_parse(&color, "#ffff00");
  gtk_color_chooser_set_rgba(GTK_COLOR_CHOOSER(widget), &color);

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "pcap_stats_pos"));
  gtk_combo_box_set_active(GTK_COMBO_BOX(widget), pref.pcap_stats_pos);

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "filter_combo"));
  model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget));
  if (!model) {
    GtkListStore *list_store;
    list_store = gtk_list_store_new(1, G_TYPE_STRING);
    gtk_combo_box_set_model(GTK_COMBO_BOX(widget), GTK_TREE_MODEL(list_store));
  }

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "center_combo"));
  model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget));
  if (!model) {
    GtkListStore *list_store;
    list_store = gtk_list_store_new(1, G_TYPE_STRING);
    gtk_combo_box_set_model(GTK_COMBO_BOX(widget), GTK_TREE_MODEL(list_store));
  }

  pref_to_color_list();         /* Updates the color preferences table with pref.colors */

  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "bck_image_enabled"));
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), pref.bck_image_enabled);
  gtk_widget_set_sensitive(GTK_WIDGET(gtk_builder_get_object(appdata.xml, "bck_image_open")),
                           pref.bck_image_enabled);

  if (pref.bck_image_path && *pref.bck_image_path) {
    widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "bck_image_open"));
    gtk_file_chooser_select_filename(GTK_FILE_CHOOSER(widget), pref.bck_image_path);
  }

  /* Connects signals */
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "diag_pref"));
  g_signal_connect(G_OBJECT(widget),
                   "delete_event",
                   G_CALLBACK(on_cancel_pref_button_clicked), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "node_radius_slider"));
  g_signal_connect(G_OBJECT(gtk_range_get_adjustment(GTK_RANGE(widget))),
                   "value_changed",
                   G_CALLBACK(on_node_radius_slider_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "inner_ring_scale_slider"));
  g_signal_connect(G_OBJECT(gtk_range_get_adjustment(GTK_RANGE(widget))),
                   "value_changed",
                   G_CALLBACK(on_inner_ring_scale_slider_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "averaging_spin"));
  g_signal_connect(G_OBJECT(gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget))),
                   "value_changed",
                   G_CALLBACK(on_averaging_spin_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "refresh_spin"));
  g_signal_connect(G_OBJECT(gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget))),
                   "value_changed",
                   G_CALLBACK(on_refresh_spin_adjustment_changed),
                   canvas_widget());
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "gui_node_to_spin"));
  g_signal_connect(G_OBJECT(gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget))),
                   "value_changed",
                   G_CALLBACK(on_gui_node_to_spin_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "proto_node_to_spin"));
  g_signal_connect(G_OBJECT(gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget))),
                   "value_changed",
                   G_CALLBACK(on_proto_node_to_spin_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "gui_link_to_spin"));
  g_signal_connect(G_OBJECT(gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget))),
                   "value_changed",
                   G_CALLBACK(on_gui_link_to_spin_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "proto_link_to_spin"));
  g_signal_connect(G_OBJECT(gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget))),
                   "value_changed",
                   G_CALLBACK(on_proto_link_to_spin_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "proto_to_spin"));
  g_signal_connect(G_OBJECT(gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget))),
                   "value_changed",
                   G_CALLBACK(on_proto_to_spin_adjustment_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "stack_level"));
  g_signal_connect(G_OBJECT(widget),
                   "changed",
                   G_CALLBACK(on_stack_level_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "size_variable"));
  g_signal_connect(G_OBJECT(widget),
                   "changed",
                   G_CALLBACK(on_size_variable_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "size_mode"));
  g_signal_connect(G_OBJECT(widget),
                   "changed",
                   G_CALLBACK(on_size_mode_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "text_font"));
  g_signal_connect(G_OBJECT(widget),
                   "font_set",
                   G_CALLBACK(on_text_font_changed), NULL);
  widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "text_color"));
  g_signal_connect(G_OBJECT(widget),
                   "color_set",
                   G_CALLBACK(on_text_color_changed), NULL);
}

void on_preferences1_activate(GtkMenuItem *menuitem, gpointer user_data)
{
  GtkComboBox *cbox;

  /* saves current prefs to a temporary */
  copy_config(&tmp_pref, &pref);

  initialize_pref_controls();

  cbox = GTK_COMBO_BOX(gtk_builder_get_object(appdata.xml, "filter_combo"));
  cbox_add_select(cbox, pref.filter);

  cbox = GTK_COMBO_BOX(gtk_builder_get_object(appdata.xml, "center_combo"));
  cbox_add_select(cbox, pref.centered_nodes);

  gtk_widget_show(diag_pref);
  gdk_window_raise(gtk_widget_get_window(diag_pref));
}

void on_node_radius_slider_adjustment_changed(GtkAdjustment *adj)
{
  double value = gtk_adjustment_get_value(adj);
  pref.node_radius_multiplier = exp(value * log(10));
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        _("Adjustment value: %g. Radius multiplier %g"),
        value, pref.node_radius_multiplier);
}

void on_inner_ring_scale_slider_adjustment_changed(GtkAdjustment *adj)
{
  double value = gtk_adjustment_get_value(adj);
  pref.inner_ring_scale = value;
  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        _("Adjustment value: %g. Inner ring scale %g"),
        value, pref.inner_ring_scale);
  ask_reposition(FALSE);
}

void on_averaging_spin_adjustment_changed(GtkAdjustment *adj)
{
  pref.averaging_time = gtk_adjustment_get_value(adj);  /* Control and value in ms */
}

void on_refresh_spin_adjustment_changed(GtkAdjustment *adj, GtkWidget *canvas)
{
  change_refresh_period(gtk_adjustment_get_value(adj));
}

void on_gui_node_to_spin_adjustment_changed(GtkAdjustment *adj)
{
  pref.gui_node_timeout_time = gtk_adjustment_get_value(adj)*MILLI;     /* value in ms */
}

void on_proto_node_to_spin_adjustment_changed(GtkAdjustment *adj)
{
  pref.proto_node_timeout_time = gtk_adjustment_get_value(adj)*MILLI;   /* value in ms */
}

void on_gui_link_to_spin_adjustment_changed(GtkAdjustment *adj)
{
  pref.gui_link_timeout_time = gtk_adjustment_get_value(adj)*MILLI;     /* value in ms */
}

void on_proto_link_to_spin_adjustment_changed(GtkAdjustment *adj)
{
  pref.proto_link_timeout_time = gtk_adjustment_get_value(adj)*MILLI;   /* value in ms */
}

void on_proto_to_spin_adjustment_changed(GtkAdjustment *adj)
{
  pref.proto_timeout_time = gtk_adjustment_get_value(adj)*MILLI;        /* value in ms */
}

static void on_size_mode_changed(GtkComboBox *combo, gpointer data)
{
  /* Beware! Size mode is an enumeration. The menu options
   * must much the enumaration values */
  pref.size_mode = (size_mode_t)gtk_combo_box_get_active(combo);
}

static void on_size_variable_changed(GtkComboBox *combo, gpointer data)
{
  /* Beware! Size variable is an enumeration. The menu options
   * must much the enumaration values */
  pref.node_size_variable = (node_size_variable_t)gtk_combo_box_get_active(combo);
}

static void on_stack_level_changed(GtkWidget *combo, gpointer data)
{
  pref.stack_level = gtk_combo_box_get_active(GTK_COMBO_BOX(combo));
  delete_gui_protocols();
}

static void on_text_font_changed(GtkFontButton *wdg, gpointer data)
{
  const gchar *str = gtk_font_button_get_font_name(wdg);
  if (str) {
    if (pref.fontname)
      g_free(pref.fontname);
    pref.fontname = g_strdup(str);
    ask_reposition(TRUE);   /* reposition and update font */
  }
}

static void on_text_color_changed(GtkColorButton *wdg, gpointer data)
{
  GdkRGBA new_color;
  gtk_color_chooser_get_rgba(GTK_COLOR_CHOOSER(wdg), &new_color);
  g_free(pref.text_color);
  pref.text_color = gdk_rgba_to_string(&new_color);
  ask_reposition(TRUE);
}

void on_diagram_only_toggle_toggled(GtkToggleButton *togglebutton,
                                    gpointer user_data)
{
  pref.diagram_only = gtk_toggle_button_get_active(togglebutton);
  ask_reposition(FALSE);
}                               /* on_diagram_only_toggle_toggled */

void on_group_unk_check_toggled(GtkToggleButton *togglebutton,
                                gpointer user_data)
{
  pref.group_unk = gtk_toggle_button_get_active(togglebutton);
}                               /* on_group_unk_check_toggled */

/*
 * confirm changes
 */
void on_ok_pref_button_clicked(GtkWidget *button, gpointer user_data)
{
  confirm_changes();
  hide_pref_dialog();
}                               /* on_ok_pref_button_clicked */


/* reset configuration to saved and close dialog */
void on_cancel_pref_button_clicked(GtkWidget *button, gpointer user_data)
{
  /* reset configuration to saved */
  copy_config(&pref, &tmp_pref);

  ask_reposition(TRUE);
  if (colors_changed) {
    protohash_read_prefvect(pref.colors);
    delete_gui_protocols();
  }

  hide_pref_dialog();
}                               /* on_cancel_pref_button_clicked */

void on_save_pref_button_clicked(GtkWidget *button, gpointer user_data)
{
  confirm_changes();    /* to save we simulate confirmation */
  save_config(&pref);
  hide_pref_dialog();
}                               /* on_save_pref_button_clicked */


/* Makes a new filter */
static void on_filter_entry_changed(GtkComboBox *cbox, gpointer user_data)
{
  const gchar *str;
  gchar *err;
  /* TODO should make sure that for each mode the filter is set up
   * correctly */
  str = gtk_entry_get_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(cbox))));
  if (pref.filter)
    g_free(pref.filter);
  pref.filter = g_strdup(str);
  err = set_filter(pref.filter);
  g_free(err);
  cbox_add_select(cbox, pref.filter);
}                               /* on_filter_entry_changed */

/* Makes a new center node */
static void on_center_node_changed(GtkComboBox *cbox, gpointer user_data)
{
  const gchar *str;
  str = gtk_entry_get_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(cbox))));
  g_free(pref.centered_nodes);
  pref.centered_nodes = g_strdup(str);
  free_nodeset_spec_list(centered_node_speclist);
  centered_node_speclist = parse_nodeset_spec_list(pref.centered_nodes);
  cbox_add_select(cbox, pref.centered_nodes);
  ask_reposition(FALSE);
}

void on_numeric_toggle_toggled(GtkToggleButton *togglebutton, gpointer user_data)
{
  pref.name_res = gtk_toggle_button_get_active(togglebutton);
}                               /* on_numeric_toggle_toggled */

void on_background_image_path_selected(GtkFileChooserButton *filechooser, gpointer user_data)
{
  pref.bck_image_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filechooser));
}       /* on_background_image_path_selected */

void on_background_image_enable_toggled(GtkToggleButton *togglebutton, gpointer user_data)
{
  gboolean on = gtk_toggle_button_get_active(togglebutton);
  pref.bck_image_enabled = on;
  gtk_widget_set_sensitive(GTK_WIDGET(gtk_builder_get_object(appdata.xml, "bck_image_open")), on);
}

void on_pcap_stats_display_changed(GtkComboBox *combobox, gpointer user_data)
{
  pref.pcap_stats_pos = gtk_combo_box_get_active(combobox);
}

/* ----------------------------------------------------------

   Color-proto preferences handling

   ---------------------------------------------------------- */

/* helper struct used to move around trees data ... */
typedef struct _EATreePos
{
  GtkTreeView *gv;
  GtkListStore *gs;
} EATreePos;

/* fill ep with the listore for the color treeview, creating it if necessary
   Returns FALSE if something goes wrong
*/
static gboolean get_color_store(EATreePos *ep)
{
  /* initializes the view ptr */
  ep->gs = NULL;
  ep->gv = GTK_TREE_VIEW(gtk_builder_get_object(appdata.xml, "color_list"));
  if (!ep->gv)
    return FALSE; /* error */

  /* retrieve the model (store) */
  ep->gs = GTK_LIST_STORE(gtk_tree_view_get_model(ep->gv));
  if (ep->gs)
    return TRUE; /* model already initialized, finished */

  /* store not found, must be created  - it uses 3 values:
     First the color string, then the gdk color, lastly the protocol */
  ep->gs = gtk_list_store_new(3,
                              G_TYPE_STRING, GDK_TYPE_RGBA, G_TYPE_STRING);
  gtk_tree_view_set_model(ep->gv, GTK_TREE_MODEL(ep->gs));

  /* the view columns and cell renderers must be also created ...
     Note: the bkg color is linked to the second column of store
   */
  gtk_tree_view_append_column(ep->gv,
                              gtk_tree_view_column_new_with_attributes
                                (_("Color"), gtk_cell_renderer_text_new(),
                                "text", 0, "background-rgba", 1, NULL));
  gtk_tree_view_append_column(ep->gv,
                              gtk_tree_view_column_new_with_attributes
                                (_("Protocol"), gtk_cell_renderer_text_new(),
                                "text", 2, NULL));

  return TRUE;
}

void on_color_edit_dialog_show(GtkWidget *wdg, gpointer user_data)
{
  gchar *protocol_string;
  GdkRGBA *color;
  GtkTreePath *gpath = NULL;
  GtkTreeViewColumn *gcol = NULL;
  GtkTreeIter it;
  GtkComboBox *cbox;
  GtkColorChooser *chos;
  EATreePos ep;

  if (!get_color_store(&ep))
    return;

  /* gets the row (path) at cursor */
  gtk_tree_view_get_cursor(ep.gv, &gpath, &gcol);
  if (gpath) {
    /* row selected */
    if (!gtk_tree_model_get_iter(GTK_TREE_MODEL(ep.gs), &it, gpath))
      return; /* path not found */

    gtk_tree_model_get(GTK_TREE_MODEL(ep.gs), &it, 1, &color, 2, &protocol_string, -1);

    cbox = GTK_COMBO_BOX(gtk_builder_get_object(appdata.xml, "protocol_entry"));
    cbox_add_select(cbox, protocol_string);

    chos = GTK_COLOR_CHOOSER(gtk_builder_get_object(appdata.xml, "color_entry"));
    gtk_color_chooser_set_rgba(chos, color);

    g_free(protocol_string);
  }
}


void on_color_add_button_clicked(GtkButton *button, gpointer user_data)
{
  GtkWidget *dlg = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "color_edit_dialog"));
  if (dlg) {
    g_object_set_data(G_OBJECT(dlg), "isadd", GINT_TO_POINTER(TRUE));
    gtk_widget_show(dlg);
  }
} 

void on_color_edit_button_clicked(GtkButton *button, gpointer user_data)
{
  GtkWidget *dlg = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "color_edit_dialog"));
  if (dlg) {
    g_object_set_data(G_OBJECT(dlg), "isadd", GINT_TO_POINTER(FALSE));
    gtk_widget_show(dlg);
  }
} 

void on_color_remove_button_clicked(GtkButton *button, gpointer user_data)
{
  GtkTreePath *gpath = NULL;
  GtkTreeViewColumn *gcol = NULL;
  GtkTreeIter it;
  EATreePos ep;
  if (!get_color_store(&ep))
    return;

  /* gets the row (path) at cursor */
  gtk_tree_view_get_cursor(ep.gv, &gpath, &gcol);
  if (!gpath)
    return; /* no row selected */

  /* get iterator from path  and removes from store */
  if (!gtk_tree_model_get_iter(GTK_TREE_MODEL(ep.gs), &it, gpath))
    return; /* path not found */

  if (gtk_list_store_remove(ep.gs, &it)) {
    /* iterator still valid, selects current pos */
    gpath = gtk_tree_model_get_path(GTK_TREE_MODEL(ep.gs), &it);
    gtk_tree_view_set_cursor(ep.gv, gpath, NULL, 0);
    gtk_tree_path_free(gpath);
  }

  colors_changed = TRUE;
  color_list_to_pref();
}

void on_colordiag_ok_clicked(GtkButton *button, gpointer user_data)
{
  GtkWidget *colorsel, *colorseldiag;
  GdkRGBA color;
  GtkTreePath *gpath = NULL;
  GtkTreeViewColumn *gcol = NULL;
  GtkTreeIter it;
  gint isadd;
  EATreePos ep;
  if (!get_color_store(&ep))
    return;

  colorseldiag = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "colorselectiondialog"));
  isadd = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(colorseldiag), "isadd"));

  /* gets the row (path) at cursor */
  gtk_tree_view_get_cursor(ep.gv, &gpath, &gcol);
  if (isadd) {
    if (gpath) {
      /* row sel, add/change color */
      GtkTreeIter itsibling;
      if (!gtk_tree_model_get_iter
            (GTK_TREE_MODEL(ep.gs), &itsibling, gpath))
        return; /* path not found */
      gtk_list_store_insert_before(ep.gs, &it, &itsibling);
    }
    else
      gtk_list_store_append(ep.gs, &it); /* no row selected, append */
  }
  else {
    if (!gpath ||
        !gtk_tree_model_get_iter(GTK_TREE_MODEL(ep.gs), &it, gpath))
      return; /* path not found */
  }

  /* get the selected color */
  colorsel = gtk_color_selection_dialog_get_color_selection(
    GTK_COLOR_SELECTION_DIALOG(colorseldiag));
  gtk_color_selection_get_current_rgba(GTK_COLOR_SELECTION(colorsel),
                                       &color);

  /* fill data */
  if (isadd)
    gtk_list_store_set(ep.gs, &it, 0, COLSPACES, 1, &color, 2, "", -1);
  else
    gtk_list_store_set(ep.gs, &it, 0, COLSPACES, 1, &color, -1);

  gtk_widget_hide(colorseldiag);

  color_list_to_pref();
  colors_changed = TRUE;
}

void on_color_edit_ok_clicked(GtkButton *button, gpointer user_data)
{
  const gchar *combo_string;
  gchar *proto_string;
  GdkRGBA color;
  GtkTreePath *gpath = NULL;
  GtkTreeViewColumn *gcol = NULL;
  GtkTreeIter it;
  GtkComboBox *cbox;
  GtkColorChooser *chos;
  gint isadd;
  EATreePos ep;
  GtkWidget *dlg;
  
  dlg = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "color_edit_dialog"));
  if (!dlg)
    return;

  if (!get_color_store(&ep))
    return;

  /* modify or add ? */
  isadd = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(dlg), "isadd"));

  cbox = GTK_COMBO_BOX(gtk_builder_get_object(appdata.xml, "protocol_entry"));
  combo_string = gtk_entry_get_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(cbox))));
  proto_string = g_utf8_strup(g_strdup(combo_string), -1);
  proto_string = remove_spaces(proto_string);
  cbox_add_select(cbox, proto_string);

  chos = GTK_COLOR_CHOOSER(gtk_builder_get_object(appdata.xml, "color_entry"));
  gtk_color_chooser_get_rgba(chos, &color);

  /* gets the row (path) at cursor */
  gtk_tree_view_get_cursor(ep.gv, &gpath, &gcol);
  if (isadd) {
    if (gpath) {
      /* row sel, add/change color */
      GtkTreeIter itsibling;
      if (!gtk_tree_model_get_iter(GTK_TREE_MODEL(ep.gs), &itsibling, gpath))
        return; /* path not found */
      gtk_list_store_insert_before(ep.gs, &it, &itsibling);
    }
    else
      gtk_list_store_append(ep.gs, &it); /* no row selected, append */
  }
  else {
    if (!gpath ||
        !gtk_tree_model_get_iter(GTK_TREE_MODEL(ep.gs), &it, gpath))
      return; /* path or node not found */
  }

  gtk_list_store_set(ep.gs, &it, 
                     0, COLSPACES, 
                     1, &color, 
                     2, proto_string, 
                     -1);

  g_free(proto_string);
  gtk_widget_hide(dlg);

  colors_changed = TRUE;
  color_list_to_pref();
}

static void pref_to_color_list(void)
{
  gint i;
  EATreePos ep;
  if (!get_color_store(&ep))
    return;

  /* clear list */
  gtk_list_store_clear(ep.gs);

  for (i = 0; pref.colors[i]; ++i) {
    GdkRGBA color;
    gchar * *colors_protocols = NULL;
    gchar *protocol = NULL;
    GtkTreeIter it;

    colors_protocols = g_strsplit(pref.colors[i], ";", 0);

    /* converting color */
    gdk_rgba_parse(&color, colors_protocols[0]);

    /* converting proto name */
    if (!colors_protocols[1])
      protocol = "";
    else
      protocol = colors_protocols[1];

    /* adds a new row */
    gtk_list_store_append(ep.gs, &it);
    gtk_list_store_set(ep.gs, &it, 0, COLSPACES, 1, &color,
                       2, protocol, -1);
    g_strfreev(colors_protocols);
  }
}

/* Called whenever preferences are applied or OKed. Copied whatever there is
 * in the color table to the color preferences in memory */
static void color_list_to_pref(void)
{
  gint i;
  gint ncolors;
  GtkTreeIter it;

  EATreePos ep;
  if (!get_color_store(&ep))
    return;

  g_strfreev(pref.colors);
  pref.colors = NULL;

  ncolors = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(ep.gs), NULL);
  pref.colors = g_malloc(sizeof(gchar *) * (ncolors+1));
  g_assert(pref.colors);

  gtk_tree_model_get_iter_first(GTK_TREE_MODEL(ep.gs), &it);
  for (i = 0; i < ncolors; i++) {
    gchar *protocol;
    GdkRGBA *color;

    /* reads the list */
    gtk_tree_model_get(GTK_TREE_MODEL(ep.gs), &it,
                       1, &color, 2, &protocol, -1);

    pref.colors[i] = g_strdup_printf("#%02x%02x%02x;%s",
                                     (unsigned int)(color->red * 255),
                                     (unsigned int)(color->green * 255),
                                     (unsigned int)(color->blue * 255),
                                     protocol);
    g_free(protocol);

    gtk_tree_model_iter_next(GTK_TREE_MODEL(ep.gs), &it);
  }
  pref.colors[ncolors] = NULL;

  pref.colors = protohash_compact(pref.colors);
  protohash_read_prefvect(pref.colors);
}

/* adds a string to the combo if not already present and loads it in the
   edit box. If str is "" simply clears the edit box */
static void cbox_add_select(GtkComboBox *cbox, const gchar *str)
{
  GtkTreeModel *model;
  GtkTreeIter iter, iter3;
  gboolean res;
  gchar *modelstr;
  GtkWidget *entry;

  if (!str)
    str = "";

  entry = gtk_bin_get_child(GTK_BIN(cbox));
  gtk_entry_set_text(GTK_ENTRY(entry), str);

  if (*str) {
    model = gtk_combo_box_get_model(GTK_COMBO_BOX(cbox));
    for (res = gtk_tree_model_get_iter_first(model, &iter);
         res;
         res = gtk_tree_model_iter_next(model, &iter)) {
      gtk_tree_model_get(model, &iter, 0, &modelstr, -1);
      if (strcmp(str, modelstr) == 0) {
        /* already present */
        g_free(modelstr);
        return;
      }
      g_free(modelstr);
    }

    gtk_list_store_insert_with_values(GTK_LIST_STORE(model),
                                      &iter3, 0, 0, str, -1);
  }
}

void change_refresh_period(guint32 newperiod)
{
  pref.refresh_period = newperiod;
  diagram_timeout_changed();
}
