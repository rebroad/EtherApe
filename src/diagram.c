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

#include <gtk/gtk.h>
#include <goocanvas.h>

#include "appdata.h"
#include "diagram.h"
#include "pref_dialog.h"
#include "stats/node.h"
#include "info_windows.h"
#include "stats/protocols.h"
#include "datastructs.h"
#include "names/ip-cache.h"
#include "menus.h"
#include "capture/capctl.h"
#include "stats/conversations.h"
#include "preferences.h"
#include "export.h"
#include "stats/util.h"

/* maximum node and link size */
#define MAX_NODE_SIZE  5000
#define MAX_LINK_SIZE  (MAX_NODE_SIZE/4)

gboolean already_updating;
gboolean stop_requested;

/***************************************************************************
 *
 * canvas_node_t definition and methods
 *
 **************************************************************************/
typedef struct
{
  node_id_t canvas_node_id;
  GooCanvasItem *node_item;
  GooCanvasItem *text_item;
  GooCanvasGroup *group_item;
  GdkRGBA color;
  gboolean is_new;
  gboolean shown;               /* True if it is to be displayed. */
  gboolean centered;            /* true if is a center node */

  /* For '-P' mode (columnar layout) */
  guint column; /* Which column this goes in */
  guint column_idx; /* Which position within its column this node is */
} canvas_node_t;

static gint canvas_node_compare(const node_id_t *a, const node_id_t *b,
                                gpointer dummy);
static void canvas_node_delete(canvas_node_t *cn);
static gint canvas_node_update(node_id_t  *ether_addr,
                               canvas_node_t *canvas_node,
                               GList * *delete_list);

/***************************************************************************
 *
 * canvas_link_t definition and methods
 *
 **************************************************************************/
typedef struct
{
  link_id_t canvas_link_id; /* id of the link */
  GooCanvasItem *src_item;    /* triangle for src side */
  GooCanvasItem *dst_item;    /* triangle for dst side */
  GdkRGBA color;
} canvas_link_t;
static gint canvas_link_compare(const link_id_t *a, const link_id_t *b,
                                gpointer dummy);
static void canvas_link_delete(canvas_link_t *canvas_link);
static gint canvas_link_update(link_id_t *link_id,
                               canvas_link_t *canvas_link,
                               GList * *delete_list);

struct node_ring
{
  gfloat angle;
  guint node_i;
  guint n_nodes;
};

typedef struct
{
  GooCanvas *canvas;

  struct node_ring outer;
  struct node_ring center;

  gdouble xmin;
  gdouble ymin;
  gdouble xmax;
  gdouble ymax;
  gdouble x_rad_max;
  gdouble y_rad_max;
  gdouble x_inner_rad_max;
  gdouble y_inner_rad_max;

  guint *column_populations;
} reposition_node_t;

/***************************************************************************
 *
 * canvas_background_t definition and methods
 *
 **************************************************************************/

typedef struct
{
  gboolean use_image;

  struct
  {
    GdkPixbuf *image;
    gchar *path;
    GooCanvasItem *item;
  } image;
} canvas_background_t;

static void init_canvas_background(GooCanvasItem *rootitem);

/***************************************************************************
 *
 * local variables
 *
 **************************************************************************/

static GTree *canvas_nodes = NULL;      /* We don't use the nodes tree directly in order to
                                 * separate data from presentation: that is, we need to
                                 * keep a list of CanvasItems, but we do not want to keep
                                 * that info on the nodes tree itself */
static GTree *canvas_links = NULL;     /* See canvas_nodes */
static guint known_protocols = 0;
static canvas_background_t canvas_background;
static guint displayed_nodes;
static gboolean need_reposition = TRUE; /* Force a diagram relayout */
static gboolean need_font_refresh = TRUE; /* Force font refresh during layout */
static gint diagram_timeout = 0;        /* Descriptor of the diagram timeout function
                                        * (Used to change the refresh_period in the callback */

static long canvas_obj_count = 0; /* counter of canvas objects */
static GooCanvas *gcanvas_ = NULL; /* drawing canvas */
static GtkContainer *garea_ = NULL; /* drawing container */
static GooCanvasText *pcap_stats_text_item = NULL;

/***************************************************************************
 *
 * local Function definitions
 *
 **************************************************************************/
static void update_diagram(GooCanvas *canvas); /* full diagram update */
static void diagram_update_nodes(GooCanvas *canvas); /* updates ALL nodes */
static void diagram_update_links(GooCanvas *canvas); /* updates ALL links */
static void diagram_update_background_image(GooCanvas *canvas); /* updates background image */
static void diagram_reposition(); /* reposition nodes */

static void check_new_protocol(GtkWidget *prot_table, const protostack_t *pstk);
static gint check_new_node(node_t *node, GooCanvas *canvas);
static gboolean display_node(node_t *node);
static void limit_nodes(void);
static gint add_ordered_node(node_id_t *node_id,
                             canvas_node_t *canvas_node,
                             GTree *ordered_nodes);
static gint check_ordered_node(gdouble *traffic, canvas_node_t *node,
                               guint *count);
static gint traffic_compare(gconstpointer a, gconstpointer b);
static gint reposition_canvas_nodes(node_id_t *node_id,
                                    canvas_node_t *canvas_node,
                                    reposition_node_t *data);
static gint reposition_canvas_nodes_prep(const node_id_t *node_id,
                                         canvas_node_t *canvas_node,
                                         reposition_node_t *data);
static gint check_new_link(link_id_t *link_id,
                           link_t *link,
                           GooCanvas *canvas);
static gdouble get_node_size(gdouble average);
static gdouble get_link_size(const basic_stats_t *link_stats);
static gint pcap_stats_text_item_event(GooCanvasItem *item, GdkEvent *event,
                                       void *unused);
static gboolean link_item_event(GooCanvasItem *item,
                                GooCanvasItem *target_item,
                                GdkEventButton *event,
                                canvas_link_t *canvas_link);
static gboolean node_item_event(GooCanvasItem *item,
                                GooCanvasItem *target_item,
                                GdkEventButton *event,
                                canvas_node_t *canvas_node);

static void update_legend(void);
static void draw_oneside_link(double xs, double ys, double xd, double yd,
                              const basic_stats_t *link_data,
                              const GdkRGBA *scaledColor, GooCanvasItem *item);
static void init_reposition(reposition_node_t *data,
                            GooCanvas *canvas,
                            guint total_nodes);
static void clear_reposition(reposition_node_t *rdata);
static void redraw_canvas_background(GooCanvas *canvas);
static gboolean diagram_resize_event(GtkWidget *widget,
                                     const GdkEventConfigure *event,
                                     GooCanvas *canvas);

/***************************************************************************
 *
 * implementation
 *
 **************************************************************************/
GtkWidget *canvas_widget()
{
  return GTK_WIDGET(gcanvas_);
}

static void goo_canvas_item_show(GooCanvasItem *it)
{
  g_object_set(G_OBJECT(it),
               "visibility", GOO_CANVAS_ITEM_VISIBLE,
               NULL);
}
static void goo_canvas_item_hide(GooCanvasItem *it)
{
  g_object_set(G_OBJECT(it),
               "visibility", GOO_CANVAS_ITEM_INVISIBLE,
               NULL);
}

void ask_reposition(gboolean r_font)
{
  need_reposition = TRUE;
  need_font_refresh = r_font;
}

void dump_stats(guint32 diff_msecs)
{
  gchar *status_string;
  long ipc = ipcache_active_entries();
  status_string = g_strdup_printf(
    _("Nodes: %d (on canvas: %d, shown: %u), Links: %d, Conversations: %ld, "
      "names %ld, protocols %ld. Total Packets seen: %lu (in memory: %ld, "
      "on list %ld). IP cache entries %ld. Canvas objs: %ld. Refreshed: %u ms"),
    node_count(),
    g_tree_nnodes(canvas_nodes), displayed_nodes,
    links_catalog_size(), active_conversations(),
    active_names(), protocol_summary_size(),
    appdata.n_packets, appdata.total_mem_packets,
    packet_list_item_count(), ipc,
    canvas_obj_count,
    (unsigned int)diff_msecs);

  g_my_info("%s", status_string);
  g_free(status_string);
}

/* called when a watched object is finalized */
static void finalize_callback(gpointer data, GObject *obj)
{
  --canvas_obj_count;
}
/* increase reference to object and optionally register a callback to check
 * for reference leaks */
static void addref_canvas_obj(GObject *obj)
{
  g_assert(obj);
  g_object_ref_sink(obj);

  if (INFO_ENABLED) {
    /* to check for resource leaks, we ask for a notify ... */
    g_object_weak_ref(obj, finalize_callback, NULL);
    ++canvas_obj_count;
  }
}


/* It updates controls from values of variables, and connects control
 * signals to callback functions */
void init_diagram(GtkBuilder *xml)
{
  GooCanvasItem *rootitem;
  GooCanvasItem *item;
  GtkAllocation windowsize;
  gulong sig_id;
//  GtkWidget *viewport;
//  GtkStyleContext *style;
//  static GdkRGBA black = {0,0,0,0};

  g_assert(gcanvas_ == NULL);

  /* get containing window and size */
  garea_ = GTK_CONTAINER(gtk_builder_get_object(xml, "diagramwindow"));
  g_assert(garea_ != NULL);
  gtk_widget_get_allocation(GTK_WIDGET(garea_), &windowsize);

  /* Creates trees */
  canvas_nodes = g_tree_new_full((GCompareDataFunc)canvas_node_compare,
                                 NULL, NULL, (GDestroyNotify)canvas_node_delete);
  canvas_links = g_tree_new_full((GCompareDataFunc)canvas_link_compare,
                                 NULL, NULL, (GDestroyNotify)canvas_link_delete);

  initialize_pref_controls();

  /* canvas */
  gcanvas_ = GOO_CANVAS(goo_canvas_new());
  g_assert(gcanvas_ != NULL);

  g_object_set(G_OBJECT(gcanvas_),
               "background-color", "black",
               NULL);

  goo_canvas_set_bounds(gcanvas_,
                        -windowsize.width/2, -windowsize.height/2,
                        windowsize.width/2, windowsize.height/2);

  gtk_widget_show(GTK_WIDGET(gcanvas_));

  gtk_container_add(garea_, GTK_WIDGET(gcanvas_));

  rootitem = goo_canvas_get_root_item(gcanvas_);

  /* Initialize background image */
  g_object_set(G_OBJECT(gcanvas_), "background-color", "black", NULL);
  init_canvas_background(rootitem);

/* TODO: gtk3 handles background color via CSS...
  // Make legend background color match main display background color
  style = gtk_style_new();
  style->bg[GTK_STATE_NORMAL] = canvas_background.color;
  style->base[GTK_STATE_NORMAL] = canvas_background.color;

  // Set protocol legend background to black
  viewport = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "legend_viewport"));
  gtk_widget_set_style(viewport, style);
  gtk_style_set_background(style, gtk_widget_get_window(viewport), GTK_STATE_NORMAL);

  // should be gtk3 compatible, but doesn't work ...
  viewport = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "legend_viewport"));
  gtk_widget_override_background_color(viewport,
                                      GTK_STATE_FLAG_NORMAL|GTK_STATE_FLAG_ACTIVE,
                                      &black);
*/

  item = goo_canvas_text_new(rootitem,
                             "",
                             0.0, 0.0, -1.0,
                             GOO_CANVAS_ANCHOR_NORTH_WEST,
                             NULL);
  pcap_stats_text_item = GOO_CANVAS_TEXT(item);
  addref_canvas_obj(G_OBJECT(pcap_stats_text_item));

  sig_id = g_signal_connect(G_OBJECT(garea_), "size-allocate",
                            G_CALLBACK(diagram_resize_event), gcanvas_);
  g_assert(sig_id > 0);
  sig_id = g_signal_connect(G_OBJECT(pcap_stats_text_item), "enter-notify-event",
                            G_CALLBACK(pcap_stats_text_item_event), NULL);
  g_assert(sig_id > 0);
  sig_id = g_signal_connect(G_OBJECT(pcap_stats_text_item), "leave-notify-event",
                            G_CALLBACK(pcap_stats_text_item_event), NULL);
  g_assert(sig_id > 0);

  /* Initialize the known_protocols table */
  delete_gui_protocols();

  /* Set the already_updating global flag */
  already_updating = FALSE;
  stop_requested = FALSE;
}

void cleanup_diagram()
{
  if (canvas_nodes)
    g_tree_destroy(canvas_nodes);
  if (canvas_links)
    g_tree_destroy(canvas_links);
}

/*
 * Initialize the canvas_background structure.
 * Create a new group and add it to the root group.
 * Create a new GooCanvasPixbufItem and add it to the new group.
 */
static void init_canvas_background(GooCanvasItem *rootitem)
{
  canvas_background.image.item =
    goo_canvas_image_new(rootitem,
                         NULL,
                         0.0, 0.0,
                         NULL);
  addref_canvas_obj(G_OBJECT(canvas_background.image.item));

  canvas_background.use_image = pref.bck_image_enabled;
  canvas_background.image.path = g_strdup(pref.bck_image_path);
}

/*
 * Called by on_canvas1_size_allocate.
 * Try to load image from path.
 * On success image is scaled to the canvas size and printed.
 * On error a blank black image is made and printed.
 */
static void redraw_canvas_background(GooCanvas *canvas)
{
  GError *error = NULL;
  GtkAllocation canvas_size;

  if (canvas_background.use_image) {
    /* Get canvas dimensions */
    gtk_widget_get_allocation(GTK_WIDGET(canvas), &canvas_size);

    if (canvas_background.image.image) {
      g_object_unref(G_OBJECT(canvas_background.image.image));
      canvas_background.image.image = NULL;
    }

    if (canvas_background.image.path && strlen(canvas_background.image.path))
      canvas_background.image.image = gdk_pixbuf_new_from_file_at_scale(canvas_background.image.path,
                                                                        canvas_size.width, canvas_size.height,
                                                                        FALSE, &error);

    g_object_set(G_OBJECT(canvas_background.image.item),
                 "pixbuf", canvas_background.image.image,
                 "x", (double)-canvas_size.width/2,
                 "y", (double)-canvas_size.height/2,
                 "visibility", GOO_CANVAS_ITEM_VISIBLE,
                 NULL);
  }
  else {
    g_object_set(G_OBJECT(canvas_background.image.item),
                 "visibility", GOO_CANVAS_ITEM_HIDDEN,
                 NULL);
  }
}

/*
 * Update the background image.  Load new image if user selected another path
 * in preferences.  Place the background image behind the nodes and links.
 */
static void diagram_update_background_image(GooCanvas *canvas)
{
  /*
   * If the background image enable toggle or the image path has changed, we
   * need to update the background.
   */
  if (pref.bck_image_enabled != canvas_background.use_image ||
      g_strcmp0(canvas_background.image.path, pref.bck_image_path)) {
    canvas_background.use_image = pref.bck_image_enabled;
    g_free(canvas_background.image.path);
    canvas_background.image.path = g_strdup(pref.bck_image_path);
    redraw_canvas_background(canvas);
  }

  /* Draw the background first */
  if (canvas_background.image.item) {
    goo_canvas_item_lower(GOO_CANVAS_ITEM(canvas_background.image.item), NULL);
    goo_canvas_item_request_update(GOO_CANVAS_ITEM(canvas_background.image.item));
  }
}

static gboolean diagram_resize_event(GtkWidget *widget,
                                     const GdkEventConfigure *event,
                                     GooCanvas *canvas)
{
  GtkAllocation windowsize;
  g_assert(widget != NULL);
  g_assert(canvas == gcanvas_);


  gtk_widget_get_allocation(GTK_WIDGET(widget), &windowsize);
  goo_canvas_set_bounds(canvas,
                        -windowsize.width/2, -windowsize.height/2,
                        windowsize.width/2, windowsize.height/2);

  redraw_canvas_background(canvas);
  diagram_reposition(canvas);
  diagram_update_links(canvas);
  return FALSE;
}


/* delete the specified canvas node */
static void canvas_node_delete(canvas_node_t *canvas_node)
{
  if (canvas_node->node_item) {
    goo_canvas_item_remove(canvas_node->node_item);
//      gtk_object_destroy(GTK_OBJECT(canvas_node->node_item));
//      g_object_unref(G_OBJECT (canvas_node->node_item));
    canvas_node->node_item = NULL;
  }
  if (canvas_node->text_item) {
    goo_canvas_item_remove(canvas_node->text_item);
//      gtk_object_destroy(GTK_OBJECT (canvas_node->text_item));
//      g_object_unref(G_OBJECT (canvas_node->text_item));
    canvas_node->text_item = NULL;
  }
  if (canvas_node->group_item) {
    goo_canvas_item_remove(GOO_CANVAS_ITEM(canvas_node->group_item));
//      gtk_object_destroy(GTK_OBJECT (canvas_node->group_item));
//      g_object_unref(G_OBJECT (canvas_node->group_item));
    canvas_node->group_item = NULL;
  }

  g_free(canvas_node);
}

/* used to remove nodes */
static void gfunc_remove_canvas_node(gpointer data, gpointer user_data)
{
  g_tree_remove(canvas_nodes, (const node_id_t *)data);
}

/* used to remove links */
static void gfunc_remove_canvas_link(gpointer data, gpointer user_data)
{
  g_tree_remove(canvas_links, (const link_id_t *)data);
}

static void diagram_update_nodes(GooCanvas *canvas)
{
  GList *delete_list = NULL;
  node_t *new_node = NULL;

  /* Check if there are any new nodes */
  while ((new_node = new_nodes_pop()))
    check_new_node(new_node, canvas);

  /* Update nodes look and queue outdated canvas_nodes for deletion */
  g_tree_foreach(canvas_nodes,
                 (GTraverseFunc)canvas_node_update,
                 &delete_list);

  /* delete all canvas nodes queued */
  g_list_foreach(delete_list, gfunc_remove_canvas_node, NULL);

  /* free the list - list items are already destroyed */
  g_list_free(delete_list);

  /* Limit the number of nodes displayed, if a limit has been set */
  /* TODO check whether this is the right function to use, now that we have a more
   * general display_node called in update_canvas_nodes */
  limit_nodes();

  /* Reposition canvas_nodes */
  if (need_reposition)
    diagram_reposition(canvas);
}

/* handle node repositioning */
static void diagram_reposition(GooCanvas *canvas)
{
  reposition_node_t rdata;

  if (pref.headless)
    return;

  init_reposition(&rdata, canvas, displayed_nodes);

  g_tree_foreach(canvas_nodes,
                 (GTraverseFunc)reposition_canvas_nodes_prep,
                 &rdata);

  rdata.center.node_i = rdata.center.n_nodes;
  rdata.outer.node_i = rdata.outer.n_nodes;

  g_tree_foreach(canvas_nodes,
                 (GTraverseFunc)reposition_canvas_nodes,
                 &rdata);

  clear_reposition(&rdata);

  need_reposition = FALSE;
  need_font_refresh = FALSE;
}

static void diagram_update_links(GooCanvas *canvas)
{
  GList *delete_list = NULL;

  if (pref.headless)
    return;

  /* Check if there are any new links */
  links_catalog_foreach((GTraverseFunc)check_new_link, canvas);

  /* Update links look
   * We also queue timedout links for deletion */
  delete_list = NULL;
  g_tree_foreach(canvas_links,
                 (GTraverseFunc)canvas_link_update,
                 &delete_list);

  /* delete all canvas links queued */
  g_list_foreach(delete_list, gfunc_remove_canvas_link, NULL);

  /* free the list - list items are already destroyed */
  g_list_free(delete_list);
}

/* Return a g_malloc()ed string of libpcap stats counters */
static gchar *get_pcap_stats_string(void)
{
  struct pcap_stat stats;

  if (appdata.source.type == ST_FILE)
    return g_strdup(_("(Capture statistics unavailable in offline mode.)"));

  get_capture_stats(&stats);

  return g_strdup_printf("%-12s %12u\n%-12s %12u\n%-12s %12u", "recv:",
                         stats.ps_recv, "drop:", stats.ps_drop,
                         "ifdrop:", stats.ps_ifdrop);
}

/* Update libpcap stats counters display */
static void update_pcap_stats_text(GooCanvas *canvas)
{
  gdouble xmin, xmax, ymin, ymax, xpos, ypos;
  GooCanvasAnchorType anchor;
  gchar *tmpstr;

  if (pref.pcap_stats_pos == STATSPOS_NONE) {
    g_object_set(G_OBJECT(pcap_stats_text_item),
                 "visibility", GOO_CANVAS_ITEM_HIDDEN,
                 NULL);
    return;
  }

  if (get_capture_status() != PLAY)
    return;

  goo_canvas_get_bounds(canvas, &xmin, &ymin, &xmax, &ymax);

  switch (pref.pcap_stats_pos)
  {
      case STATSPOS_UPPER_LEFT:
        xpos = xmin;
        ypos = ymin;
        anchor = GOO_CANVAS_ANCHOR_NORTH_WEST;
        break;

      case STATSPOS_UPPER_RIGHT:
        xpos = xmax;
        ypos = ymin;
        anchor = GOO_CANVAS_ANCHOR_NORTH_EAST;
        break;

      case STATSPOS_LOWER_LEFT:
        xpos = xmin;
        ypos = ymax;
        anchor = GOO_CANVAS_ANCHOR_SOUTH_WEST;
        break;

      case STATSPOS_LOWER_RIGHT:
        xpos = xmax;
        ypos = ymax;
        anchor = GOO_CANVAS_ANCHOR_SOUTH_EAST;
        break;

      default:
        g_error(_("Bogus statspos_t (%d) pref.pcap_stats_pos"), pref.pcap_stats_pos);
        return;
  }

  tmpstr = get_pcap_stats_string();
  g_object_set(G_OBJECT(pcap_stats_text_item),
               "text", tmpstr,
               "x", xpos, "y", ypos,
               "font", pref.fontname,
               "fill_color", pref.text_color,
               "anchor", anchor,
               "visibility", GOO_CANVAS_ITEM_VISIBLE,
               NULL);
  g_free(tmpstr);
}

/* Refreshes the diagram. Called each refresh_period ms
 * 1. Checks for new protocols and displays them
 * 2. Updates nodes looks
 * 3. Updates links looks
 */
static void update_diagram(GooCanvas *canvas)
{
  capstatus_t status;

  /* if requested and enabled, dump to xml */
  if (appdata.request_dump && appdata.export_file_signal) {
    g_warning(_("SIGUSR1 received: exporting to %s"), appdata.export_file_signal);
    dump_xml(appdata.export_file_signal, appdata.n_packets);
    appdata.request_dump = FALSE;
  }

  status = get_capture_status();
  if (status == PAUSE)
    return;

  if (status == CAP_EOF) {
    gui_eof_capture();

    if (pref.headless)
      gtk_main_quit();

#if DEBUG_TIMINGS
    /* after capture stops, update the time in 100ms steps for debugging */
    static struct timeval incr;
    incr.tv_sec = 0;
    incr.tv_usec = 100000;
    timeradd(&appdata.now, &incr, &appdata.now);
#else
    return;  /* after replaying do not update the display anymore */
#endif        
  }

  /*
   * It could happen that during an intensive calculation, in order
   * to update the GUI and make the application responsive gtk_main_iteration
   * is called. But that could also trigger this very function's timeout.
   * If we let it run twice many problems could come up. Thus,
   * we are preventing it with the already_updating variable
   */

  if (already_updating) {
    g_my_debug("update_diagram called while already updating");
    return;
  }

  already_updating = TRUE;

  if (!pref.headless || appdata.max_delay) {
    /* headless with max delay zero disables also node expiration */ 

    /* Deletes all nodes and updates traffic values */
    nodes_catalog_update_all();

    /* Delete old capture links and update capture link variables */
    links_catalog_update_all();

    /* Update global protocol information */
    protocol_summary_update_all();
  }

  if (!pref.headless) {

    /* update background image */
    diagram_update_background_image(canvas);

    /* update nodes */
    diagram_update_nodes(canvas);

    /* update links */
    diagram_update_links(canvas);

    /* update proto legend */
    update_legend();

    /* Now update info windows */
    update_info_windows(NULL);

    update_pcap_stats_text(canvas);
  }

  /* Force redraw */
  while (gtk_events_pending())
    gtk_main_iteration();

  already_updating = FALSE;

  if (stop_requested)
    gui_stop_capture();
}

static void purge_expired_legend_protocol(GtkWidget *widget, gpointer data)
{
  GtkLabel *lab = GTK_LABEL(widget);
  if (lab &&
      !protocol_summary_find(pref.stack_level, gtk_label_get_label(lab))) {
    /* protocol expired, remove */
    gtk_widget_destroy(widget);
    known_protocols--;
  }
}

/* updates the legend */
static void update_legend()
{
  GtkWidget *prot_table;

  /* first, check if there are expired protocols */
  prot_table = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "prot_table"));
  if (!prot_table)
    return;

  gtk_container_foreach(GTK_CONTAINER(prot_table),
                        (GtkCallback)purge_expired_legend_protocol, NULL);

  /* then search for new protocols */
  check_new_protocol(prot_table, protocol_summary_stack());
}


/* Checks whether there is already a legend entry for each known
 * protocol. If not, create it */
static void check_new_protocol(GtkWidget *prot_table, const protostack_t *pstk)
{
  const GList *protocol_item;
  const protocol_t *protocol;
  const GdkRGBA *color;
//  GtkStyle *style;
  GtkLabel *lab;
  GtkWidget *newlab;
  GList *childlist;
  gchar *mkupbuf = NULL;

  if (!pstk)
    return; /* nothing to do */

  childlist = gtk_container_get_children(GTK_CONTAINER(prot_table));
  protocol_item = pstk->protostack[pref.stack_level];
  while (protocol_item) {
    const GList *cur;
    protocol = protocol_item->data;

    /* prepare next */
    protocol_item = protocol_item->next;

    /* First, we check whether the diagram already knows about this protocol,
     * checking whether it is shown on the legend. */
    cur = childlist;
    while (cur) {
      lab = GTK_LABEL(cur->data);
      if (lab && !strcmp(protocol->name, gtk_label_get_label(lab)))
        break; /* found */
      cur = cur->next;
    }

    if (cur)
      continue; /* found, skip to next */

    g_my_debug("Protocol '%s' not found. Creating legend item",
               protocol->name);

    /* It's not, so we build a new entry on the legend */


    /* we add the new label widgets */
    newlab = gtk_label_new(NULL);
    gtk_widget_show(newlab);
//      gtk_misc_set_alignment(GTK_MISC(newlab), 0, 0);

    color = protohash_color(protocol->name);
    mkupbuf = g_markup_printf_escaped(
      "<span foreground=\"#%02x%02x%02x\">%s</span>",
      (unsigned int)(color->red * 255),
      (unsigned int)(color->green * 255),
      (unsigned int)(color->blue * 255),
      protocol->name);
    gtk_label_set_markup(GTK_LABEL(newlab), mkupbuf);
    g_free(mkupbuf);

/*      if (!gdk_colormap_alloc_color
          (gdk_colormap_get_system(), &color, FALSE, TRUE))
        g_warning (_("Unable to allocate color for new protocol %s"),
                   protocol->name);
      style = gtk_style_new ();
      style->fg[GTK_STATE_NORMAL] = color;
      gtk_widget_set_style (newlab, style);
      g_object_unref (style);
*/

    gtk_container_add(GTK_CONTAINER(prot_table), newlab);
    known_protocols++;
  }
  g_list_free(childlist);
}                               /* check_new_protocol */

/* empties the table of protocols */
void delete_gui_protocols(void)
{
  GList *item;
  GtkContainer *prot_table;

  known_protocols = 0;

  /* restart color cycle */
  protohash_reset_cycle();

  /* remove proto labels from legend */
  prot_table = GTK_CONTAINER(gtk_builder_get_object(appdata.xml, "prot_table"));
  item = gtk_container_get_children(GTK_CONTAINER(prot_table));
  while (item) {
    gtk_container_remove(prot_table, item->data);
    item = item->next;
  }

  gtk_widget_queue_resize(GTK_WIDGET(appdata.app1));
}                               /* delete_gui_protocols */

/* Checks if there is a canvas_node per each node. If not, one canvas_node
 * must be created and initiated */
static gint check_new_node(node_t *node, GooCanvas *canvas)
{
  canvas_node_t *new_canvas_node;
  gulong sig_id;

  if (!node)
    return FALSE;

  if (display_node(node) && !g_tree_lookup(canvas_nodes, &node->node_id)) {
    GooCanvasItem *rootgroup;
    GooCanvasItem *newgroup;

    new_canvas_node = g_malloc(sizeof(canvas_node_t));
    g_assert(new_canvas_node);

    new_canvas_node->canvas_node_id = node->node_id;

    /* Create a new group to hold the node and its labels */
    rootgroup = goo_canvas_get_root_item(canvas);
    newgroup = goo_canvas_group_new(rootgroup,
                                    "x", 100.0,
                                    "y", 100.0,
                                    NULL);
    addref_canvas_obj(G_OBJECT(newgroup));
    new_canvas_node->group_item = GOO_CANVAS_GROUP(newgroup);

    /* create circle and text, initially hidden until proper repositioned */
    new_canvas_node->node_item = goo_canvas_ellipse_new(newgroup,
                                                        0.0,
                                                        0.0,
                                                        0.0,
                                                        0.0,
                                                        "fill-color", "white",
                                                        "stroke-color", "black",
                                                        "line-width", 0.0,
                                                        "visibility", GOO_CANVAS_ITEM_INVISIBLE,
                                                        NULL);
    addref_canvas_obj(G_OBJECT(new_canvas_node->node_item));

    new_canvas_node->text_item = goo_canvas_text_new(newgroup,
                                                     node->name->str,
                                                     0.0,
                                                     0.0,
                                                     -1.0,
                                                     GOO_CANVAS_ANCHOR_CENTER,
                                                     "font", pref.fontname,
                                                     "fill-color", pref.text_color,
                                                     "visibility", GOO_CANVAS_ITEM_INVISIBLE,
                                                     NULL);
    addref_canvas_obj(G_OBJECT(new_canvas_node->text_item));

    goo_canvas_item_raise(new_canvas_node->text_item, NULL);
    sig_id = g_signal_connect(G_OBJECT(new_canvas_node->text_item),
                              "button-release-event",
                              G_CALLBACK(node_item_event),
                              new_canvas_node);
    g_assert(sig_id > 0);
    sig_id = g_signal_connect(G_OBJECT(new_canvas_node->node_item),
                              "button-release-event",
                              G_CALLBACK(node_item_event),
                              new_canvas_node);
    g_assert(sig_id > 0);

    if (!new_canvas_node->node_item || !new_canvas_node->text_item)
      g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, _("Canvas node null"));

    new_canvas_node->is_new = TRUE;
    new_canvas_node->shown = TRUE;
    new_canvas_node->centered = FALSE;

    g_tree_insert(canvas_nodes,
                  &new_canvas_node->canvas_node_id, new_canvas_node);
    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
          _("Creating canvas_node: %s. Number of nodes %d"),
          node->name->str, g_tree_nnodes(canvas_nodes));

    need_reposition = TRUE;
  }

  return FALSE;                 /* False to keep on traversing */
}                               /* check_new_node */


/* - updates sizes, names, etc */
static gint canvas_node_update(node_id_t *node_id, canvas_node_t *canvas_node,
                               GList * *delete_list)
{
  node_t *node;
  gdouble node_size;
  static clock_t start = 0;
  clock_t end;
  gdouble cpu_time_used;
  char *nametmp = NULL;
  const gchar *main_prot;

  node = nodes_catalog_find(node_id);

  /* Remove node if node is too old or if capture is stopped */
  if (!node || !display_node(node)) {
    /* adds current to list of canvas nodes to delete */
    *delete_list = g_list_prepend(*delete_list, node_id);
    g_my_debug("Queueing canvas node to remove.");
    need_reposition = TRUE;
    return FALSE;
  }

  switch (pref.node_size_variable)
  {
      case INST_TOTAL:
        node_size = get_node_size(node->node_stats.stats.average);
        break;
      case INST_INBOUND:
        node_size = get_node_size(node->node_stats.stats_in.average);
        break;
      case INST_OUTBOUND:
        node_size = get_node_size(node->node_stats.stats_out.average);
        break;
      case INST_PACKETS:
        node_size = get_node_size(node->node_stats.pkt_list.length);
        break;
      case ACCU_TOTAL:
        node_size = get_node_size(node->node_stats.stats.accumulated);
        break;
      case ACCU_INBOUND:
        node_size = get_node_size(node->node_stats.stats_in.accumulated);
        break;
      case ACCU_OUTBOUND:
        node_size = get_node_size(node->node_stats.stats_out.accumulated);
        break;
      case ACCU_PACKETS:
        node_size = get_node_size(node->node_stats.stats.accu_packets);
        break;
      case ACCU_AVG_SIZE:
        node_size = get_node_size(node->node_stats.stats.avg_size);
        break;
      default:
        node_size = get_node_size(node->node_stats.stats_out.average);
        g_warning(_("Unknown value or node_size_variable"));
  }

  /* limit the maximum size to avoid overload */
  if (node_size > MAX_NODE_SIZE)
    node_size = MAX_NODE_SIZE;

  main_prot = traffic_stats_most_used_proto(&node->node_stats, pref.stack_level);
  if (main_prot) {
    canvas_node->color = *protohash_color(main_prot);

    g_object_set(G_OBJECT(canvas_node->node_item),
                 "radius-x", node_size / 2,
                 "radius-y", node_size / 2,
                 "fill-color-gdk-rgba", &canvas_node->color,
                 "visibility", GOO_CANVAS_ITEM_VISIBLE,
                 NULL);
    goo_canvas_item_show(canvas_node->text_item);
  }
  else {
    guint32 black = 0x000000ff;
    g_object_set(G_OBJECT(canvas_node->node_item),
                 "radius-x", node_size / 2,
                 "radius-y", node_size / 2,
                 "fill_color_rgba", black,
                 "visibility", GOO_CANVAS_ITEM_VISIBLE,
                 NULL);
  }

  /* We check the name of the node, and update the canvas node name
   * if it has changed (useful for non blocking dns resolving) */
  if (canvas_node->text_item) {
    g_object_get(G_OBJECT(canvas_node->text_item),
                 "text", &nametmp,
                 NULL);
    if (strcmp(nametmp, node->name->str)) {
      g_object_set(G_OBJECT(canvas_node->text_item),
                   "text", node->name->str,
                   NULL);
      goo_canvas_item_request_update(canvas_node->text_item);
    }
    g_free(nametmp);
  }

  /* Processor time check. If too much time has passed, update the GUI */
  end = clock();
  cpu_time_used = ((gdouble)(end - start)) / CLOCKS_PER_SEC;
  if (cpu_time_used > 0.05) {
    /* Force redraw */
    while (gtk_events_pending())
      gtk_main_iteration();
    start = end;
  }
  return FALSE;                 /* False means keep on calling the function */
}                               /* update_canvas_nodes */


/* Returns whether the node in question should be displayed in the
 * diagram or not */
static gboolean display_node(node_t *node)
{
  double diffms;

  if (!node)
    return FALSE;

  diffms = subtract_times_ms(&appdata.now, &node->node_stats.stats.last_time);

  /* There are problems if a canvas_node is deleted if it still
   * has packets, so we have to check that as well */

  /* Remove canvas_node if node is too old */
  if (diffms >= pref.gui_node_timeout_time &&
      pref.gui_node_timeout_time &&
      !node->node_stats.pkt_list.length)
    return FALSE;

#if 1
  if ((pref.gui_node_timeout_time == 1) && !node->node_stats.pkt_list.length)
    g_my_critical("Impossible situation in display node");
#endif

  return TRUE;
}                               /* display_node */

/* Sorts canvas nodes with the criterium set in preferences and sets
 * which will be displayed in the diagram */
static void limit_nodes(void)
{
  GTree *ordered_nodes = NULL;
  guint limit;

  displayed_nodes = 0;          /* We'll increment for each node we don't
                                 * limit */

  if (appdata.node_limit < 0) {
    displayed_nodes = g_tree_nnodes(canvas_nodes);
    return;
  }

  limit = appdata.node_limit;

  ordered_nodes = g_tree_new(traffic_compare);

  g_tree_foreach(canvas_nodes, (GTraverseFunc)add_ordered_node, ordered_nodes);
  g_tree_foreach(ordered_nodes, (GTraverseFunc)check_ordered_node,
                 &limit);
  g_tree_destroy(ordered_nodes);
}                               /* limit_nodes */

static gint add_ordered_node(node_id_t *node_id, canvas_node_t *node,
                             GTree *ordered_nodes)
{
  g_tree_insert(ordered_nodes, node, node);
  g_my_debug("Adding ordered node. Number of nodes: %d",
             g_tree_nnodes(ordered_nodes));
  return FALSE;                 /* keep on traversing */
}                               /* add_ordered_node */

static gint check_ordered_node(gdouble *traffic, canvas_node_t *node, guint *count)
{
  /* TODO We can probably optimize this by stopping the traversion once
   * the limit has been reached */
  if (*count) {
    if (!node->shown)
      need_reposition = TRUE;
    node->shown = TRUE;
    ++displayed_nodes;
    (*count)--;
  }
  else {
    if (node->shown)
      need_reposition = TRUE;
    node->shown = FALSE;
  }
  return FALSE;            /* keep on traversing */
}

/* Comparison function used to order the (GTree *) nodes
 * and canvas_nodes heard on the network */
static gint traffic_compare(gconstpointer a, gconstpointer b)
{
  node_t *node_a, *node_b;

  g_assert(a != NULL);
  g_assert(b != NULL);

  node_a = (node_t *)a;
  node_b = (node_t *)b;

  if (node_a->node_stats.stats.average < node_b->node_stats.stats.average)
    return 1;
  if (node_a->node_stats.stats.average > node_b->node_stats.stats.average)
    return -1;

  /* If two nodes have the same traffic, we still have
   * to distinguish them somehow. We use the node_id */

  return (node_id_compare(&node_a->node_id, &node_b->node_id));
}                               /* traffic_compare */

/* initialize reposition struct */
static void init_reposition(reposition_node_t *data,
                            GooCanvas *canvas,
                            guint total_nodes)
{
  gdouble text_compensation = 50;

  data->canvas = canvas;
  memset(&data->center, 0, sizeof(data->center));
  memset(&data->outer, 0, sizeof(data->outer));

  /*
   * Offset the starting angle on the center ring so that when there are
   * relatively few nodes displayed (e.g. 4 central and 4 outer) the links
   * obscure things less (by not overlapping node labels and other links).
   */
  data->center.angle += M_PI / 4.0;

  if (appdata.column_patterns)
    data->column_populations = g_malloc0(appdata.column_patterns->len + 1 *
                                         sizeof(*data->column_populations));

  goo_canvas_get_bounds(canvas,
                        &data->xmin, &data->ymin,
                        &data->xmax, &data->ymax);


  data->xmin += text_compensation;
  data->xmax -= text_compensation;      /* Reduce the drawable area so that
                                 * the node name is not lost
                                 * TODO: Need a function to calculate
                                 * text_compensation depending on font size */
  data->x_rad_max = 0.9 * (data->xmax - data->xmin) / 2;
  data->y_rad_max = 0.9 * (data->ymax - data->ymin) / 2;
  data->x_inner_rad_max = data->x_rad_max / 2;
  data->y_inner_rad_max = data->y_rad_max / 2;
}

static void clear_reposition(reposition_node_t *rdata)
{
  if (appdata.column_patterns)
    g_free(rdata->column_populations);
}

static guint find_node_column(node_t *node)
{
  guint i;

  /* This should only be called if we're in columnar-positioning mode */
  g_assert(appdata.column_patterns);

  for (i = 0; i < appdata.column_patterns->len; i++) {
    if (node_matches_spec_list(node, g_ptr_array_index(appdata.column_patterns, i)))
      return i;
  }

  /*
   * If no explicit match was found it goes in the rightmost column (with an
   * implicit "match-all" pattern).
   */
  return appdata.column_patterns->len;
}

/*
 * A preparatory pass to count how many nodes are centered and how many are on
 * the outer ring (and mark each appropriately).  Also does analogous work for
 * columnar-positioning mode (count nodes in each column and mark each node with
 * its column).
 */
static gint reposition_canvas_nodes_prep(const node_id_t *node_id,
                                         canvas_node_t *canvas_node,
                                         reposition_node_t *rdata)
{
  node_t *node;

  if (!canvas_node->shown)
    return FALSE;

  node = nodes_catalog_find(node_id);
  if (appdata.column_patterns) {
    canvas_node->column = find_node_column(node);
    canvas_node->column_idx = rdata->column_populations[canvas_node->column]++;
  }
  else if (node && node_matches_spec_list(node, centered_node_speclist)) {
    canvas_node->centered = TRUE;
    rdata->center.n_nodes++;
  }
  else {
    canvas_node->centered = FALSE;
    rdata->outer.n_nodes++;
  }

  return FALSE;
}

/*
 * Return a point between 'min' and 'max' appropriate for position number 'pos'
 * out of 'num' total possible positions (basically pos/num of the way between
 * min and max, though with some tweaking to keep things away from the very
 * edges of the range).
 */
static gdouble scale_within(gdouble min, gdouble max, guint pos, guint num)
{
  return min + (((max - min) / (num + 1)) * (pos + 1));
}

/* Called from update_diagram if the global need_reposition
 * is set. It rearranges the nodes*/
static gint reposition_canvas_nodes(node_id_t *node_id,
                                    canvas_node_t *canvas_node,
                                    reposition_node_t *data)
{
  struct node_ring *ring;
  gdouble center_x, center_y, oddAngle;
  gdouble x = 0, y = 0;

  if (!canvas_node->shown) {
    goo_canvas_item_hide(canvas_node->node_item);
    goo_canvas_item_hide(canvas_node->text_item);
    return FALSE;
  }

  ring = canvas_node->centered ? &data->center : &data->outer;

  center_x = (data->xmax - data->xmin) / 2 + data->xmin;
  center_y = (data->ymax - data->ymin) / 2 + data->ymin;

  /* TODO I've done all the stationary changes in a hurry
   * I should review it an tidy up all this stuff */
  if (appdata.stationary_layout) {
    if (canvas_node->is_new) {
      static guint count = 0, base = 1;
      gdouble s_angle = 0;

      if (count == 0) {
        s_angle = M_PI * 2.0f;
        count++;
      }
      else {
        if (count > 2 * base) {
          base *= 2;
          count = 1;
        }
        s_angle = M_PI * (gdouble)count / ((gdouble)base);
        count += 2;
      }
      x = data->x_rad_max * cos(s_angle);
      y = data->y_rad_max * sin(s_angle);
    }
  }
  else if (appdata.column_patterns) {
    guint col = canvas_node->column;

    x = scale_within(data->xmin, data->xmax, canvas_node->column,
                     appdata.column_patterns->len + 1);
    y = scale_within(data->ymin, data->ymax, canvas_node->column_idx,
                     data->column_populations[col]);
  }
  else {
    if (canvas_node->centered && data->center.n_nodes == 1) {
      /* one centered node, reset coordinates */
      x = center_x;
      y = center_y;
      ring->angle -= 2 * M_PI / ring->n_nodes;
    }
    else {
      if (ring->n_nodes % 2 == 0) /* spacing is better when n_nodes is odd and Y is linear */
        oddAngle = (ring->angle * ring->n_nodes) / (ring->n_nodes + 1);
      else
        oddAngle = ring->angle;

      if (ring->n_nodes > 7) {
        x = data->x_rad_max * cos(oddAngle);
        y = data->y_rad_max * asin(sin(oddAngle)) / (M_PI / 2);
      }
      else {
        x = data->x_rad_max * cos(ring->angle);
        y = data->y_rad_max * sin(ring->angle);
      }

      if (canvas_node->centered && data->center.n_nodes > 1) {
        /* For the inner ring, just move it proportionally closer the the center point. */
        x = center_x + ((x - center_x) * pref.inner_ring_scale);
        y = center_y + ((y - center_y) * pref.inner_ring_scale);
      }
    }
  }


  if (!appdata.stationary_layout || canvas_node->is_new) {
    g_object_set(G_OBJECT(canvas_node->group_item),
                 "x", x,
                 "y", y,
                 NULL);
    canvas_node->is_new = FALSE;
  }

  if (need_font_refresh) {
    /* update text font */
    g_object_set(G_OBJECT(canvas_node->text_item),
                 "font", pref.fontname,
                 "fill_color", pref.text_color,
                 NULL);
  }

  if (pref.diagram_only) {
    goo_canvas_item_hide(canvas_node->text_item);
  }
  else {
    goo_canvas_item_show(canvas_node->text_item);
    goo_canvas_item_request_update(canvas_node->text_item);
  }

  goo_canvas_item_show(canvas_node->node_item);
  goo_canvas_item_request_update(canvas_node->node_item);

  ring->node_i--;

  if (ring->node_i)
    ring->angle += 2 * M_PI / ring->n_nodes;
  else {
    ring->angle = 0.0;
    ring->n_nodes = 0;
  }

  return FALSE;
}


/* Goes through all known links and checks whether there already exists
 * a corresponding canvas_link. If not, create it.*/
static gint check_new_link(link_id_t *link_id, link_t *link, GooCanvas *canvas)
{
  canvas_link_t *new_canvas_link;
  gulong sig_id;
  GooCanvasItem *rootgroup;

  if (!g_tree_lookup(canvas_links, link_id)) {
    rootgroup = goo_canvas_get_root_item(canvas);

    new_canvas_link = g_malloc(sizeof(canvas_link_t));
    g_assert(new_canvas_link);
    new_canvas_link->canvas_link_id = *link_id;

    /* set the lines position using groups positions */
    new_canvas_link->src_item =
      goo_canvas_polyline_new(rootgroup, TRUE, 2,
                              0.0, 0.0,
                              1.0, 1.0,
                              "fill-color", "tan",
                              "line-width", 0.5,
                              NULL);
    g_object_ref(G_OBJECT(new_canvas_link->src_item));

    new_canvas_link->dst_item =
      goo_canvas_polyline_new(rootgroup, TRUE, 2,
                              0.0, 0.0,
                              1.0, 1.0,
                              "fill-color", "tan",
                              "line-width", 0.5,
                              NULL);
    g_object_ref(G_OBJECT(new_canvas_link->dst_item));


    g_tree_insert(canvas_links,
                  &new_canvas_link->canvas_link_id, new_canvas_link);
    goo_canvas_item_lower(new_canvas_link->src_item, NULL);
    goo_canvas_item_lower(new_canvas_link->dst_item, NULL);

    sig_id = g_signal_connect(G_OBJECT(new_canvas_link->src_item),
                              "button-release-event",
                              G_CALLBACK(link_item_event),
                              new_canvas_link);
    g_assert(sig_id > 0);
    sig_id = g_signal_connect(G_OBJECT(new_canvas_link->dst_item),
                              "button-release-event",
                              G_CALLBACK(link_item_event),
                              new_canvas_link);

    sig_id = g_signal_connect(G_OBJECT(new_canvas_link->src_item),
                              "enter-notify-event",
                              G_CALLBACK(link_item_event),
                              new_canvas_link);
    g_assert(sig_id > 0);
    sig_id = g_signal_connect(G_OBJECT(new_canvas_link->src_item),
                              "leave-notify-event",
                              G_CALLBACK(link_item_event),
                              new_canvas_link);
    g_assert(sig_id > 0);
  }

  return FALSE;
}


/* - calls update_links, so that the related link updates its average
 *   traffic and main protocol, and old links are deleted
 * - caculates link size and color fading */
static gint canvas_link_update(link_id_t *link_id, canvas_link_t *canvas_link,
                               GList * *delete_list)
{
  const link_t *link;
  const canvas_node_t *canvas_dst;
  const canvas_node_t *canvas_src;
  GdkRGBA scaledColor;
  double xs, ys, xd, yd, scale;
  const gchar *main_prot;

  /* We used to run update_link here, but that was a major performance penalty,
   * and now it is done in update_diagram */
  link = links_catalog_find(link_id);
  if (!link) {
    *delete_list = g_list_prepend(*delete_list, link_id);
    g_my_debug("Queueing canvas link to remove.");
    return FALSE;
  }

  /* If either source or destination has disappeared, we hide the link
       * until it can be show again */

  /* We get coords for the destination node */
  canvas_dst = g_tree_lookup(canvas_nodes, &link_id->dst);
  if (!canvas_dst || !canvas_dst->shown) {
    goo_canvas_item_hide(canvas_link->src_item);
    goo_canvas_item_hide(canvas_link->dst_item);
    return FALSE;
  }

  /* We get coords from source node */
  canvas_src = g_tree_lookup(canvas_nodes, &link_id->src);
  if (!canvas_src || !canvas_src->shown) {
    goo_canvas_item_hide(canvas_link->src_item);
    goo_canvas_item_hide(canvas_link->dst_item);
    return FALSE;
  }

  /* What if there never is a protocol?
   * I have to initialize canvas_link->color to a known value */
  main_prot = traffic_stats_most_used_proto(&link->link_stats, pref.stack_level);
  if (main_prot) {
    double diffms;
    double ratio;
    canvas_link->color = *protohash_color(main_prot);

    diffms = subtract_times_ms(&appdata.now, &link->link_stats.stats.last_time);
    ratio = diffms / pref.averaging_time;
    scale = pow(0.5, ratio);
    if (scale < 0.1) {
      /* too dark, just hide */
      goo_canvas_item_hide(canvas_link->src_item);
      goo_canvas_item_hide(canvas_link->dst_item);
      return FALSE;
    }


    scaledColor.red = scale * canvas_link->color.red;
    scaledColor.green = scale * canvas_link->color.green;
    scaledColor.blue = scale * canvas_link->color.blue;
    scaledColor.alpha = 1;
  }
  else {
    // black
    scaledColor.red = 0;
    scaledColor.green = 0;
    scaledColor.blue = 0;
    scaledColor.alpha = 1;
  }

  /* retrieve coordinates of node centers */
  g_object_get(G_OBJECT(canvas_src->group_item), "x", &xs, "y", &ys, NULL);
  g_object_get(G_OBJECT(canvas_dst->group_item), "x", &xd, "y", &yd, NULL);

  /* first draw triangle for src->dst */
  draw_oneside_link(xs, ys, xd, yd, &(link->link_stats.stats_out), &scaledColor,
                    canvas_link->src_item);

  /* then draw triangle for dst->src */
  draw_oneside_link(xd, yd, xs, ys, &(link->link_stats.stats_in), &scaledColor,
                    canvas_link->dst_item);

  return FALSE;
} 

/* given the src and dst node centers, plus a size, draws a triangle in the
 * specified color on the provided canvas item*/
static void draw_oneside_link(double xs, double ys, double xd, double yd,
                              const basic_stats_t *link_stats,
                              const GdkRGBA *scaledColor, GooCanvasItem *item)
{
  GooCanvasPoints *points;
  gdouble versorx, versory, modulus, link_size;

  link_size = get_link_size(link_stats) / 2;

  /* limit the maximum size to avoid overload */
  if (link_size > MAX_LINK_SIZE)
    link_size = MAX_LINK_SIZE;

  versorx = -(yd - ys);
  versory = xd - xs;
  modulus = sqrt(pow(versorx, 2) + pow(versory, 2));
  if (modulus == 0) {
    link_size = 0;
    modulus = 1;
  }

  points = goo_canvas_points_new(3);
  points->coords[0] = xd;
  points->coords[1] = yd;
  points->coords[2] = xs + versorx * link_size / modulus;
  points->coords[3] = ys + versory * link_size / modulus;
  points->coords[4] = xs - versorx * link_size / modulus;
  points->coords[5] = ys - versory * link_size / modulus;

  /* If we got this far, the link can be shown. Make sure it is */
  g_object_set(G_OBJECT(item),
               "points", points,
               "line-width", 0.5,
               "fill-color-gdk-rgba", scaledColor,
               "stroke-color-gdk-rgba", scaledColor,
               "visibility", GOO_CANVAS_ITEM_VISIBLE,
               NULL);

  goo_canvas_points_unref(points);
}



/* Returs the radius in pixels given average traffic and size mode */
static gdouble get_node_size(gdouble average)
{
  gdouble result = 0.0;
  switch (pref.size_mode)
  {
      case LINEAR:
        result = average + 1;
        break;
      case LOG:
        result = log(average + 1);
        break;
      case SQRT:
        result = sqrt(average + 1);
        break;
  }
  return 5.0 + pref.node_radius_multiplier * result;
}

/* Returs the width in pixels given average traffic and size mode */
static gdouble get_link_size(const basic_stats_t *link_stats)
{
  gdouble result = 0.0;
  gdouble data;

  /* since links are one-sided, there's no distinction between inbound/outbound
     data.   */
  switch (pref.node_size_variable)
  {
      case INST_TOTAL:
      case INST_INBOUND:
      case INST_OUTBOUND:
      case INST_PACKETS: /* active packets stat not available */
        data = link_stats->average;
        break;
      case ACCU_TOTAL:
      case ACCU_INBOUND:
      case ACCU_OUTBOUND:
        data = link_stats->accumulated;
        break;
      case ACCU_PACKETS:
        data = link_stats->accu_packets;
        break;
      case ACCU_AVG_SIZE:
        data = link_stats->avg_size;
        break;
      default:
        data = link_stats->average;
        g_warning(_("Unknown value for link_size_variable"));
  }
  switch (pref.size_mode)
  {
      case LINEAR:
        result = data + 1;
        break;
      case LOG:
        result = log(data + 1);
        break;
      case SQRT:
        result = sqrt(data + 1);
        break;
  }
  return 1.0 + pref.node_radius_multiplier * result;
}



/* Called for every event a link receives. Right now it's used to
 * set a message in the statusbar and launch the popup */
static gboolean link_item_event(GooCanvasItem *item,
                                GooCanvasItem *target_item,
                                GdkEventButton *event,
                                canvas_link_t *canvas_link)
{
  gchar *str;
  const gchar *main_prot = NULL;
  const link_t *link = NULL;

  switch (event->type)
  {
      case GDK_BUTTON_PRESS:
      case GDK_BUTTON_RELEASE:
      case GDK_2BUTTON_PRESS:
      case GDK_3BUTTON_PRESS:
        if (canvas_link)
          link_info_window_create(&canvas_link->canvas_link_id);
        break;

      case GDK_ENTER_NOTIFY:
        if (canvas_link)
          link = links_catalog_find(&canvas_link->canvas_link_id);
        if (link)
          main_prot = traffic_stats_most_used_proto(&link->link_stats, pref.stack_level);
        if (main_prot)
          str = g_strdup_printf(_("Link main protocol: %s"), main_prot);
        else
          str = g_strdup_printf(_("Link main protocol: unknown"));
        gtk_statusbar_push(appdata.statusbar, 1, str);
        g_free(str);
        break;
      case GDK_LEAVE_NOTIFY:
        gtk_statusbar_pop(appdata.statusbar, 1);
        break;
      default:
        break;
  }

  return FALSE;
}                               /* link_item_event */


/* Called for every event a node receives. Right now it's used to
 * launch the popup */
static gint node_item_event(GooCanvasItem *item,
                            GooCanvasItem *target_item,
                            GdkEventButton *event,
                            canvas_node_t *canvas_node)
{
//  gdouble item_x, item_y;
  const node_t *node = NULL;

  /* This is not used yet, but it will be. */
/*  item_x = event->button.x;
  item_y = event->button.y;
  gnome_canvas_item_w2i (item->parent, &item_x, &item_y);
*/
  switch (event->type)
  {
      case GDK_BUTTON_PRESS:
      case GDK_BUTTON_RELEASE:
      case GDK_2BUTTON_PRESS:
      case GDK_3BUTTON_PRESS:
        if (canvas_node)
          node = nodes_catalog_find(&canvas_node->canvas_node_id);
        if (node) {
          node_protocols_window_create(&canvas_node->canvas_node_id);
          g_my_info("Nodes: %d (shown %u)", nodes_catalog_size(),
                    displayed_nodes);
          if (DEBUG_ENABLED) {
            gchar *msg = node_dump(node);
            g_my_debug("%s", msg);
            g_free(msg);
          }
        }
        break;
      default:
        break;
  }

  return FALSE;
}                               /* node_item_event */

/* Explain pcap stats in status bar when moused over */
static gint pcap_stats_text_item_event(GooCanvasItem *item, GdkEvent *event,
                                       void *unused)
{
  switch (event->type)
  {
      case GDK_ENTER_NOTIFY:
        gtk_statusbar_push(appdata.statusbar, 1, _("'recv': packets received; "
                                                   "'drop': packets dropped by OS buffering; "
                                                   "'ifdrop': packets dropped by interface or driver."));
        break;

      case GDK_LEAVE_NOTIFY:
        gtk_statusbar_pop(appdata.statusbar, 1);
        break;

      default:
        break;
  }

  return FALSE;
}

/* Pushes a string into the statusbar stack */
void set_statusbar_msg(gchar *str)
{
  static gchar *status_string = NULL;

  if (status_string)
    g_free(status_string);

  status_string = g_strdup(str);

  gtk_statusbar_pop(appdata.statusbar, 0);
  gtk_statusbar_push(appdata.statusbar, 0, status_string);
}                               /* set_statusbar_msg */


static gint canvas_node_compare(const node_id_t *a, const node_id_t *b,
                                gpointer dummy)
{
  g_assert(a != NULL);
  g_assert(b != NULL);
  return node_id_compare(a, b);
}

static gint canvas_link_compare(const link_id_t *a, const link_id_t *b,
                                gpointer dummy)
{
  g_assert(a != NULL);
  g_assert(b != NULL);
  return link_id_compare(a, b);
}

static void canvas_link_delete(canvas_link_t *canvas_link)
{
  /* Right now I'm not very sure in which cases there could be a canvas_link but not a link_item, but
  * I had a not in update_canvas_nodes that if the test is not done it can lead to corruption */
  if (canvas_link->src_item) {
    goo_canvas_item_remove(canvas_link->src_item);
    canvas_link->src_item = NULL;
  }
  if (canvas_link->dst_item) {
    goo_canvas_item_remove(canvas_link->dst_item);
    canvas_link->dst_item = NULL;
  }

  g_free(canvas_link);
}

/* diagram timeout was changed. Remove old timer and register new */
void diagram_timeout_changed(void)
{
  if (diagram_timeout)
    g_source_remove(diagram_timeout);
  diagram_timeout = g_timeout_add(pref.refresh_period,
                                  update_diagram_callback,
                                  NULL);
}

void resize_diagram(const GtkAllocation *allocation)
{
  goo_canvas_set_bounds(gcanvas_,
                        -allocation->width / 2,
                        -allocation->height / 2,
                        allocation->width / 2,
                        allocation->height / 2);
  ask_reposition(FALSE);
  redraw_canvas_background(gcanvas_);
  update_diagram(gcanvas_);
}

gboolean update_diagram_callback(gpointer data)
{
  update_diagram(gcanvas_);
  return TRUE;
}

gboolean refresh_diagram(void)
{
  GtkAllocation windowsize;
  /* Simulate a window resize */
  g_my_debug("repaint diagram requested");
  gtk_widget_get_allocation(GTK_WIDGET(garea_), &windowsize);
  goo_canvas_set_bounds(gcanvas_,
                        -windowsize.width/2, -windowsize.height/2,
                        windowsize.width/2, windowsize.height/2);
  redraw_canvas_background(gcanvas_);
  diagram_reposition(gcanvas_);
  diagram_update_links(gcanvas_);
  return TRUE;
}
