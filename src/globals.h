/* EtherApe
 * Copyright (C) 2001 Juan Toledo
 * $Id$
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef ETHERAPE_GLOBALS_H
#define ETHERAPE_GLOBALS_H

#include <gnome.h>
#include <sys/time.h>
#include <pcap.h>
#include <glade/glade.h>

#define ETHERAPE_GLADE_FILE "etherape.glade"
#define STACK_SIZE 4		/* How many protocol levels to keep
				 * track of (+1) */

/* Enumerations */

/* Since gdb does understand enums and not defines, and as 
 * way to make an easier transition to a non-pcap etherape,
 * I define my own enum for link type codes */
typedef enum
{
  L_NULL = DLT_NULL,		/* no link-layer encapsulation */
  L_EN10MB = DLT_EN10MB,	/* Ethernet (10Mb) */
  L_EN3MB = DLT_EN3MB,		/* Experimental Ethernet (3Mb) */
  L_AX25 = DLT_AX25,		/* Amateur Radio AX.25 */
  L_PRONET = DLT_PRONET,	/* Proteon ProNET Token Ring */
  L_CHAOS = DLT_CHAOS,		/* Chaos */
  L_IEEE802 = DLT_IEEE802,	/* IEEE 802 Networks */
  L_ARCNET = DLT_ARCNET,	/* ARCNET */
  L_SLIP = DLT_SLIP,		/* Serial Line IP */
  L_PPP = DLT_PPP,		/* Point-to-point Protocol */
  L_FDDI = DLT_FDDI,		/* FDDI */
  L_ATM_RFC1483 = DLT_ATM_RFC1483,	/* LLC/SNAP encapsulated atm */
  L_RAW = DLT_RAW,		/* raw IP */
  L_SLIP_BSDOS = DLT_SLIP_BSDOS,	/* BSD/OS Serial Line IP */
  L_PPP_BSDOS = DLT_PPP_BSDOS	/* BSD/OS Point-to-point Protocol */
}
link_type_t;

typedef enum
{
  /* Beware! The value given by the option widget is dependant on
   * the order set in glade! */
  LINEAR = 0,
  LOG = 1,
  SQRT = 2
}
size_mode_t;

typedef enum
{
  INST_TOTAL = 0,
  INST_INBOUND = 1,
  INST_OUTBOUND = 2,
  ACCU_TOTAL = 3,
  ACCU_INBOUND = 4,
  ACCU_OUTBOUND = 5
}
node_size_variable_t;

typedef enum
{
  DEFAULT = -1,
  ETHERNET = 0,
  FDDI = 1,
  IEEE802 = 2,
  IP = 3,
  IPX = 4,
  TCP = 5,
  UDP = 6
}
apemode_t;

/* Flag to indicate whether a packet belongs to a node or a link */
/* TODO This has to go, it should be a packet property */
enum packet_belongs
{
  NODE = 0, LINK = 1
};

/* Flag used in node packets to indicate whether this packet was
 * inbound or outbound for the parent node */
typedef enum
{
  INBOUND = 0, OUTBOUND = 1
}
packet_direction;

/* Possible states of capture status */
enum status_t
{
  STOP = 0, PLAY = 1, PAUSE = 2
};

/* Capture structures */

typedef struct
{
  guint8 *node_id;
  GString *name;
  GString *numeric_name;
  gboolean solved;
  gdouble accumulated;
  gdouble n_packets;
}
name_t;

typedef struct
{
  guint8 *node_id;		/* pointer to the node identification
				 * could be an ether or ip address*/
  GString *name;		/* String with a readable default name of the node */
  GString *numeric_name;	/* String with a numeric representation of the id */
  guint32 ip_address;		/* Needed by the resolver */
  GString *numeric_ip;		/* Ugly hack for ethernet mode */
  gdouble average;		/* Average bytes in or out in the last x ms */
  gdouble average_in;		/* Average bytes in in the last x ms */
  gdouble average_out;		/* Average bytes out in the last x ms */
  gdouble accumulated;		/* Accumulated bytes */
  gdouble accumulated_in;	/* Accumulated incoming bytes */
  gdouble accumulated_out;	/* Accumulated outcoming bytes */
  gdouble aver_accu;		/* Accumulated bytes in the last x ms */
  gdouble aver_accu_in;		/* Accumulated incoming bytes in the last x ms */
  gdouble aver_accu_out;	/* Accumulated outcoming bytes in the last x ms */
  gdouble n_packets;		/* Number of total packets received */
  struct timeval last_time;	/* Timestamp of the last packet to be added */
  GList *packets;		/* List of packets sizes in or out and
				 * its sizes. Used to calculate average
				 * traffic */
  gchar *main_prot[STACK_SIZE + 1];	/* Most common protocol for the node */
  GList *protocols[STACK_SIZE + 1];	/* It's a stack. Each level is a list of
					 * all protocols heard at that level */

}
node_t;

/* Link information */
typedef struct
{
  guint8 *link_id;		/* pointer to guint8 containing src and
				 * destination nodes_id's of the link */
  gdouble average;
  gdouble accumulated;
  guint n_packets;
  struct timeval last_time;	/* Timestamp of the last packet added */
  GList *packets;		/* List of packets heard on this link */
  gchar *main_prot[STACK_SIZE + 1];	/* Most common protocol for the link */
  GList *protocols[STACK_SIZE + 1];	/* It's a stack. Each level is a list of 
					 * all protocols heard at that level */
  gchar *src_name;
  gchar *dst_name;
}
link_t;

/* Information about each packet heard on the network */
typedef struct
{
  guint size;			/* Size in bytes of the packet */
  struct timeval timestamp;	/* Time at which the packet was heard */
  gchar *prot;			/* Packet protocol tree */
  guint ref_count;		/* How many structures are referencing this 
				 * packet. When the count reaches zero the packet
				 * is deleted */
  guint8 *src_id;		/* Source and destination ids for the packet */
  guint8 *dst_id;		/* Useful to identify direction in node_packets */
}
packet_t;

/* Information about each protocol heard on a link */
typedef struct
{
  gchar *name;			/* Name of the protocol */
  gdouble average;		/* Average bytes in or out in the last x ms */
  gdouble aver_accu;		/* Accumulated bytes in the last x ms */
  gdouble accumulated;		/* Accumulated traffic in bytes for this protocol */
  guint n_packets;		/* Number of packets containing this protocol */
  GdkColor color;		/* The color associated with this protocol. It's here
				 * so that I can use the same structure and lookup functions
				 * in capture.c and diagram.c */
  GList *node_names;		/* Has a list of all node names used with this
				 * protocol (used in node protocols) */
  GList *node_ids;		/* Has a list of all the nodes that have used this
				 * protocol (used in the global protocols list) */
}
protocol_t;

/* Diagram structures */

typedef struct
{
  guint8 *canvas_node_id;
  node_t *node;
  GnomeCanvasItem *node_item;
  GnomeCanvasItem *text_item;
  GnomeCanvasGroup *group_item;
  GdkColor color;
  gboolean is_new;
  gboolean shown;		/* True if it is to be displayed. */
}
canvas_node_t;

typedef struct
{
  guint8 *canvas_link_id;
  link_t *link;
  GnomeCanvasItem *link_item;
  GdkColor color;
}
canvas_link_t;

GTree *canvas_nodes;		/* We don't use the nodes tree directly in order to 
				 * separate data from presentation: that is, we need to
				 * keep a list of CanvasItems, but we do not want to keep
				 * that info on the nodes tree itself */
GTree *canvas_links;		/* See above */

/* Variables */

GladeXML *xml;
GtkWidget *app1;		/* Pointer to the main app window */
GtkWidget *diag_pref;		/* Pointer to the diagram configuration window */
struct timeval now;		/* Set both at each packet capture and 
				 * in each redraw of the diagram */
GTree *nodes;			/* Has all the nodes heard on the network */
GTree *links;			/* Has all links heard on the net */
GList *protocols[STACK_SIZE + 1];	/* It's a stack. Each level is a list of 
					 * all protocols heards at that level */

link_type_t linktype;		/* Type of device we are listening to */
guint node_id_length;		/* Length of the node_id key. Depends
				 * on the mode of operation */
guint l3_offset;		/* Offset to the level 3 protocol data
				 * Depends of the linktype */
enum status_t status;		/* Keeps capture status (playing, stopped, paused) */
gboolean end_of_file;		/* Marks that the end of the offline file
				 * has been reached */

/* Genereral settings */

gchar *input_file;		/* Capture file to read from */
gboolean numeric;		/* Whether dns lookups are performed */
gboolean dns;			/* Negation of the above. Is used by dns.c */
gint diagram_timeout;		/* Descriptor of the diagram timeout function
				 * (Used to change the refresh_period in the callback */
apemode_t mode;			/* Mode of operation. Can be
				 * ETHERNET, IP, UDP or TCP */

/* Diagram settings */

gboolean diagram_only;		/* Do not use text on the diagram */
gboolean nofade;		/* Do not fade unused links */
gboolean stationary;		/* Use alternative algorith for node placing */
guint32 refresh_period;		/* Time between diagram refreshes */
gdouble node_radius_multiplier;	/* used to calculate the radius of the
				 * displayed nodes. So that the user can
				 * select with certain precision this
				 * value, the GUI uses the log10 of the
				 * multiplier */
gdouble link_width_multiplier;	/* Same explanation as above */
size_mode_t size_mode;		/* Default mode for node size and
				 * link width calculation */
node_size_variable_t node_size_variable;	/* Default variable that sets the node
						 * size */
gchar *node_color, *link_color, *text_color;	/* Default colors 
						 * TODO do we need link_color anymore? */
gchar *fontname;		/* Font to be used for text display */
gboolean need_reposition;	/* Force a diagram relayout */
guint stack_level;		/* Which level of the protocol stack 
				 * we will concentrate on */
gint node_limit;		/* Max number of nodes to show. If <0 it's not
				 * limited */
gdouble gui_node_timeout_time;	/* After this time has passed with no traffic
				 * for a node, it disappears from the diagram */
GList *legend_protocols;


/* Capture settings */

gdouble averaging_time;		/* Microseconds of time we consider to
				 * calculate traffic averages */
gdouble link_timeout_time;	/* After this time
				 * has passed with no traffic in a 
				 * link, it disappears */
gdouble node_timeout_time;	/* After this time has passed 
				 * with no traffic in/out a
				 * node, it is deleted from memory */
gchar *interface;		/* Network interface to listen to */
gchar *filter;			/* Pcap filter to be used */


/* Global functions declarations */

/* From capture.c */
gchar *init_capture (void);
gboolean start_capture (void);
gboolean pause_capture (void);
gboolean stop_capture (void);
gint set_filter (gchar * filter, gchar * device);
void update_nodes (void);
void update_links (void);
void update_protocols (void);
node_t *ape_get_new_node (void);	/* Returns a new node that hasn't been heard of */
struct timeval substract_times (struct timeval a, struct timeval b);
gint node_id_compare (gconstpointer a, gconstpointer b);
gint link_id_compare (gconstpointer a, gconstpointer b);
gint protocol_compare (gconstpointer a, gconstpointer b);
gchar *ip_to_str (const guint8 * ad);
gchar *ether_to_str (const guint8 * ad);
gchar *ether_to_str_punct (const guint8 * ad, char punct);
void dump_node_info (node_t * node);

/* From protocols.c */
gchar *get_packet_prot (const guint8 * packet, guint len);

/* From names.c */
void get_packet_names (GList ** protocols,
		       const guint8 * packet,
		       guint16 size,
		       const gchar * prot_stack, packet_direction direction);

/* From diagram.c */
guint update_diagram (GtkWidget * canvas);
void init_diagram (void);
void destroying_timeout (gpointer data);
void destroying_idle (gpointer data);
void set_appbar_status (gchar * str);
void delete_gui_protocols (void);
gchar *traffic_to_str (gdouble traffic, gboolean is_speed);

/* From menus.c */
void init_menus (void);
void fatal_error_dialog (const gchar * message);
void update_history (GnomeEntry * gentry, const gchar * str,
		     gboolean is_fileentry);
void gui_start_capture (void);
void gui_pause_capture (void);
void gui_stop_capture (void);

/* From info_windows.c */
guint update_info_windows (void);
void update_protocols_window (void);
void update_node_info_windows (void);
void create_node_info_window (canvas_node_t * canvas_node);

/* Macros */


#define g_my_debug(format, args...)      g_log (G_LOG_DOMAIN, \
						  G_LOG_LEVEL_DEBUG, \
						  format, ##args)
#define g_my_info(format, args...)      g_log (G_LOG_DOMAIN, \
						  G_LOG_LEVEL_INFO, \
						  format, ##args)
#define g_my_critical(format, args...)      g_log (G_LOG_DOMAIN, \
						      G_LOG_LEVEL_CRITICAL, \
						      format, ##args)

#define IS_OLDER(diff, timeout)        ((diff.tv_sec > timeout/1000) | \
					    (diff.tv_usec/1000 >= timeout))



/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 */
#define pntohs(p)  ((guint16)                       \
		       ((guint16)*((guint8 *)p+0)<<8|  \
			   (guint16)*((guint8 *)p+1)<<0))

#define pntohl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
		       (guint32)*((guint8 *)p+1)<<16|  \
		       (guint32)*((guint8 *)p+2)<<8|   \
		       (guint32)*((guint8 *)p+3)<<0)

/* Takes the hi_nibble value from a byte */
#define hi_nibble(b) ((b & 0xf0) >> 4)

#endif
