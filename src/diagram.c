#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gnome.h>

#include "interface.h"
#include "support.h"
#include "math.h"
#include "resolv.h"
#include "diagram.h"

/* Global application parameters */

double node_radius_multiplier_control = 3;	/* The multiplier is a positive number */
double node_radius_multiplier = 1000;	/* used to calculate the radius of the
					 * displayed nodes. So that the user can
					 * select with certain precision this
					 * value, the GUI uses the log of the
					 * multiplier in multiplier_control */

double averaging_time = 2000000;	/* Microseconds of time we consider to
					 * calculate traffic averages */
double link_timeout_time = 5000000;	/* After this time
					 * has passed with no traffic in a 
					 * link, it disappears */

GTree *canvas_nodes;		/* We don't use the nodes tree directly in order to 
				 * separate data from presentation: that is, we need to
				 * keep a list of CanvasItems, but we do not want to keep
				 * that info on the nodes tree itself */
GTree *canvas_links;		/* See above */



/* Extern functions declarations */

extern gint ether_compare (gconstpointer a, gconstpointer b);
extern gint link_compare (gconstpointer a, gconstpointer b);
extern gboolean diagram_only;


/* Local functions definitions */

gdouble
get_node_size (gdouble average)
{
  return (double) 5 + node_radius_multiplier * average;
}

gdouble
get_link_size (gdouble average)
{
  return (double) 1000 * average;
}

static gint
node_item_event (GnomeCanvasItem * item, GdkEvent * event, canvas_node_t *canvas_node)
{

  double item_x, item_y;
  static GtkWidget *node_popup;
  GtkLabel *label;


  item_x = event->button.x;
  item_y = event->button.y;
  gnome_canvas_item_w2i (item->parent, &item_x, &item_y);

  switch (event->type)
    {

    case GDK_BUTTON_PRESS:
      node_popup = create_node_popup ();
      label=(GtkLabel *)lookup_widget(GTK_WIDGET(node_popup),"name");
      gtk_label_set_text (label, canvas_node->node->name->str);
      label=(GtkLabel *)lookup_widget(GTK_WIDGET(node_popup),"ip_str");
      gtk_label_set_text (label, canvas_node->node->ip_str->str);
      label=(GtkLabel *)lookup_widget(GTK_WIDGET(node_popup),"ip_numeric_str");
      gtk_label_set_text (label, canvas_node->node->ip_numeric_str->str);
      label=(GtkLabel *)lookup_widget(GTK_WIDGET(node_popup),"ether_str");
      gtk_label_set_text (label, canvas_node->node->ether_str->str);
      label=(GtkLabel *)lookup_widget(GTK_WIDGET(node_popup),"ether_numeric_str");
      gtk_label_set_text (label, canvas_node->node->ether_numeric_str->str);
      label=(GtkLabel *)lookup_widget(GTK_WIDGET(node_popup),"accumulated");
      gtk_label_set_text (label,
			  g_strdup_printf ("%g",canvas_node->node->accumulated));
      label=(GtkLabel *)lookup_widget(GTK_WIDGET(node_popup),"average");
      gtk_label_set_text (label,
			  g_strdup_printf ("%g", canvas_node->node->average*1000000));
      gtk_widget_show (GTK_WIDGET (node_popup));
      break;
    case GDK_BUTTON_RELEASE:
      gtk_widget_destroy (GTK_WIDGET (node_popup));
    default:
      break;
    }

  return FALSE;

}

gint
reposition_canvas_nodes (guint8 * ether_addr, canvas_node_t * canvas_node, GtkWidget * canvas)
{
  static gfloat angle = 0.0;
  static guint node_i = 0, n_nodes = 0;
  double x, y, xmin, ymin, xmax, ymax, rad_max, text_compensation = 50;


  gnome_canvas_get_scroll_region (GNOME_CANVAS (canvas),
				  &xmin,
				  &ymin,
				  &xmax,
				  &ymax);
  if (!n_nodes)
    {
      n_nodes = node_i = g_tree_nnodes (canvas_nodes);
    }

  xmin += text_compensation;
  xmax -= text_compensation;	/* Reduce the drawable area so that
				 * the node name is not lost
				 * TODO: Need a function to calculate
				 * text_compensation depending on font size */
  rad_max = ((xmax - xmin) > (ymax - ymin)) ? 0.9 * (y = (ymax - ymin)) / 2 : 0.9 * (x = (xmax - xmin)) / 2;
  x = rad_max * cosf (angle);
  y = rad_max * sinf (angle);

  gnome_canvas_item_set (GNOME_CANVAS_ITEM (canvas_node->group_item),
			 "x", x,
			 "y", y,
			 NULL);
  if (diagram_only)
    {
      gnome_canvas_item_hide (canvas_node->text_item);
    }
  else
    {
      gnome_canvas_item_show (canvas_node->text_item);
      gnome_canvas_item_request_update (canvas_node->text_item);
    }

  node_i--;

  if (node_i)
    {
      angle += 2 * M_PI / n_nodes;
    }
  else
    {
      angle = 0.0;
      n_nodes = 0;
    }

  return FALSE;
}				/* reposition_canvas_nodes */


gint
update_canvas_links (guint8 * ether_link, canvas_link_t * canvas_link, GtkWidget * canvas)
{
  link_t *link;
  GnomeCanvasPoints *points;
  canvas_node_t *canvas_node;
  GtkArg args[2];
  gdouble link_size;

  link = canvas_link->link;


  /* First we check whether the link has timed out */

  update_packet_list (link->packets, LINK);

  if (link->n_packets == 0)
    {
      guint8 *ether_addr;

      gtk_object_destroy (GTK_OBJECT (canvas_link->link_item));


      g_tree_remove (canvas_links, ether_link);
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
	     _ ("Removing link and canvas_link: %s-%s. Number of links %d"),
	     get_ether_name (ether_link + 6),
	     get_ether_name (ether_link),
	     g_tree_nnodes (canvas_links));
      ether_addr = link->ether_link;
      g_free (link);
      g_tree_remove (links, ether_link);
      g_free (ether_addr);

      return TRUE;		/* I've checked it's not safe to traverse 
				 * while deleting, so we return TRUE to stop
				 * the traversion (Does that word exist? :-) */
    }


  args[0].name = "x";
  args[1].name = "y";

  points = gnome_canvas_points_new (2);

  /* We get coords from source node */
  canvas_node = g_tree_lookup (canvas_nodes, ether_link);
  gtk_object_getv (GTK_OBJECT (canvas_node->group_item),
		   2,
		   args);
  points->coords[0] = args[0].d.double_data;
  points->coords[1] = args[1].d.double_data;

  /* And then for the destination node */
  canvas_node = g_tree_lookup (canvas_nodes, ether_link + 6);
  gtk_object_getv (GTK_OBJECT (canvas_node->group_item),
		   2,
		   args);
  points->coords[2] = args[0].d.double_data;
  points->coords[3] = args[1].d.double_data;

  link->average = link->accumulated/averaging_time; 
  link_size = get_link_size (link->average);

  gnome_canvas_item_set (canvas_link->link_item,
			 "points", points,
			 "fill_color", "tan",
			 "outline_color", "black",
			 "width_units", link_size,
			 NULL);

  gnome_canvas_points_unref (points);

  return FALSE;

}				/* update_canvas_links */

gint
update_canvas_nodes (guint8 * ether_addr, canvas_node_t * canvas_node, GtkWidget * canvas)
{
  node_t *node;
  gdouble node_size;
  node = canvas_node->node;

  node->average = node->accumulated/averaging_time;
  node_size = get_node_size (node->average);


  gnome_canvas_item_set (canvas_node->node_item,
			 "x1", -node_size / 2,
			 "x2", node_size / 2,
			 "y1", -node_size / 2,
			 "y2", node_size / 2,
			 NULL);

  return FALSE;

}				/* update_canvas_nodes */

gint
check_new_link (guint8 * ether_link, link_t * link, GtkWidget * canvas)
{
  canvas_link_t *new_canvas_link;
  canvas_node_t *canvas_node;
  GnomeCanvasGroup *group;
  GnomeCanvasPoints *points;
  gdouble link_size;

  GtkArg args[2];
  args[0].name = "x";
  args[1].name = "y";



  if (!g_tree_lookup (canvas_links, ether_link))
    {
      group = gnome_canvas_root (GNOME_CANVAS (canvas));

      new_canvas_link = g_malloc (sizeof (canvas_link_t));
      new_canvas_link->ether_link = ether_link;
      new_canvas_link->link = link;

      /* We set the lines position using groups positions */
      points = gnome_canvas_points_new (2);

      /* We get coords from source node */
      canvas_node = g_tree_lookup (canvas_nodes, ether_link);
      gtk_object_getv (GTK_OBJECT (canvas_node->group_item),
		       2,
		       args);
      points->coords[0] = args[0].d.double_data;
      points->coords[1] = args[1].d.double_data;

      /* And then for the destination node */
      canvas_node = g_tree_lookup (canvas_nodes, ether_link + 6);
      gtk_object_getv (GTK_OBJECT (canvas_node->group_item),
		       2,
		       args);
      points->coords[2] = args[0].d.double_data;
      points->coords[3] = args[1].d.double_data;
       
      link->average=link->accumulated/averaging_time,
      link_size = get_link_size (link->average);

      new_canvas_link->link_item = gnome_canvas_item_new (group,
					   gnome_canvas_polygon_get_type (),
							  "points", points,
						      "fill_color", "green",
						   "outline_color", "green",
					       "width_units", link_size,
							  NULL);


      g_tree_insert (canvas_links, ether_link, new_canvas_link);
      gnome_canvas_item_lower_to_bottom (new_canvas_link->link_item);

      gnome_canvas_points_unref (points);

      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
	     _ ("Creating canvas_link: %s-%s. Number of links %d"),
	     get_ether_name ((new_canvas_link->ether_link) + 6),
	     get_ether_name (new_canvas_link->ether_link),
	     g_tree_nnodes (canvas_links));

    }

  return FALSE;
}				/* check_new_link */



gint
check_new_node (guint8 * ether_addr, node_t * node, GtkWidget * canvas)
{
  canvas_node_t *new_canvas_node;
  GnomeCanvasGroup *group;
  gdouble node_size;


  if (!g_tree_lookup (canvas_nodes, ether_addr))
    {
      group = gnome_canvas_root (GNOME_CANVAS (canvas));

      new_canvas_node = g_malloc (sizeof (canvas_node_t));
      new_canvas_node->ether_addr = ether_addr;
      new_canvas_node->node = node;
      node->average=node->accumulated/averaging_time;
      node_size = get_node_size (node->average);

      group = GNOME_CANVAS_GROUP (gnome_canvas_item_new (group,
					     gnome_canvas_group_get_type (),
							 "x", 0.0,
							 "y", 0.0,
							 NULL));

      new_canvas_node->node_item = gnome_canvas_item_new (group,
						  GNOME_TYPE_CANVAS_ELLIPSE,
							  "x1", 0.0,
							"x2", node_size,
							  "y1", 0.0,
							"y2", node_size,
					      "fill_color_rgba", 0xFF0000FF,
						   "outline_color", "black",
							  "width_pixels", 0,
							  NULL);
      new_canvas_node->text_item = gnome_canvas_item_new (group
						     ,GNOME_TYPE_CANVAS_TEXT
						    ,"text", node->name->str
							  ,"x", 0.0
							  ,"y", 0.0
						,"anchor", GTK_ANCHOR_CENTER
		       ,"font", "-misc-fixed-medium-r-*-*-*-140-*-*-*-*-*-*"
						      ,"fill_color", "black"
							  ,NULL);
      new_canvas_node->group_item = group;

      gnome_canvas_item_raise_to_top (GNOME_CANVAS_ITEM (new_canvas_node->text_item));
      gtk_signal_connect (GTK_OBJECT (new_canvas_node->group_item), "event",
			  (GtkSignalFunc) node_item_event,
			  new_canvas_node);

      g_tree_insert (canvas_nodes, ether_addr, new_canvas_node);
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, \
	     _ ("Creating canvas_node: %s. Number of nodes %d"), \
	     get_ether_name (new_canvas_node->ether_addr), \
	     g_tree_nnodes (canvas_nodes));

    }

  return FALSE;
}				/* check_new_node */

guint
update_diagram (GtkWidget * canvas)
{
  static guint n_nodes = 0, n_nodes_new;
  guint n_links = 0, n_links_new = 1;

  /* Check if there are any new nodes */
  g_tree_traverse (nodes,
		   (GTraverseFunc) check_new_node,
		   G_IN_ORDER,
		   canvas);

  /* Reposition canvas_nodes 
   * TODO: This should be conditional. Look for a way to know
   * whether the canvas needs updating, that is, a new node has been added
   */
  if (n_nodes != (n_nodes_new = g_tree_nnodes (nodes)))
    {
      g_tree_traverse (canvas_nodes,
		       (GTraverseFunc) reposition_canvas_nodes,
		       G_IN_ORDER,
		       canvas);
      n_nodes = n_nodes_new;
    }

  /* Update nodes aspect */
  g_tree_traverse (canvas_nodes,
		   (GTraverseFunc) update_canvas_nodes,
		   G_IN_ORDER,
		   canvas);

  /* Check if there are any new links */
  g_tree_traverse (links,
		   (GTraverseFunc) check_new_link,
		   G_IN_ORDER,
		   canvas);

  /* Update links aspect 
   * We also delete timedout links, and when we do that we stop
   * traversing, so we need to go on until we have finished updating */

  do
    {
      n_links = g_tree_nnodes (links);
      g_tree_traverse (canvas_links,
		       (GTraverseFunc) update_canvas_links,
		       G_IN_ORDER,
		       canvas);
      n_links_new = g_tree_nnodes (links);
    }
  while (n_links != n_links_new);

  return TRUE;			/* Keep on calling this function */

}				/* update_diagram */

void
init_diagram (void)
{
  canvas_nodes = g_tree_new (ether_compare);
  canvas_links = g_tree_new (link_compare);
}
