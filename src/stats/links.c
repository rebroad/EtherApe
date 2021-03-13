/* EtherApe
 * Copyright (C) 2001 Juan Toledo, 2005 Riccardo Ghetta
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

#include "appdata.h"
#include "protocols.h"
#include "links.h"
#include "node.h"
#include "preferences.h"
#include "conversations.h"
#include "util.h"

struct xml_tvs_helper
{
  double total_size;
  unsigned long total_packets;
  gchar *msg;
};


static GTree *all_links = NULL;                 /* Has all links heard on the net */

/* sort protocols by accumulated size */
static void link_protocol_sort(link_t *link);
static gchar *link_xml(link_t *link);

/***************************************************************************
 *
 * link_id_t implementation
 *
 **************************************************************************/
/* Comparison function used to order the (GTree *) links
 * and canvas_links heard on the network */
gint link_id_compare(const link_id_t *a, const link_id_t *b)
{
  int i;
  g_return_val_if_fail(a != NULL, 1);  /* This shouldn't happen.
                                         * We arbitrarily passing 1 to
                                         * the comparison */
  g_return_val_if_fail(b != NULL, 1);

  i = node_id_compare(&a->src, &b->src);
  if (i != 0)
    return i;

  return node_id_compare(&a->dst, &b->dst);
}                               /* link_id_compare */

/* returns a NEW gchar * with the node names of the link_id */
gchar *link_id_node_names(const link_id_t *link_id)
{
  const node_t *src_node, *dst_node;

  src_node = nodes_catalog_find(&link_id->src);
  dst_node = nodes_catalog_find(&link_id->dst);
  if (!src_node || !dst_node ||
      !src_node->name->str || !dst_node->name->str)
    return g_strdup(""); /* invalid info */

  return g_strdup_printf("%s-%s",
                         src_node->name->str,
                         dst_node->name->str);
}

gchar *link_id_xml(const link_id_t *id)
{
  gchar *nodea;
  gchar *nodeb;
  gchar *xml;
  g_assert(id);

  nodea = node_id_xml(&id->src);
  nodeb = node_id_xml(&id->dst);
  xml = g_strdup_printf("<src>\n%s</src>\n<dst>\n%s</dst>\n",
                         nodea,
                         nodeb);
  g_free(nodea);
  g_free(nodeb);

  return xml;
}


/***************************************************************************
 *
 * link_t implementation
 *
 **************************************************************************/
static gint update_link(link_id_t *link_id, link_t *link, gpointer delete_list_ptr);

/* creates a new link object */
link_t *link_create(const link_id_t *link_id)
{
  link_t *link;

  link = g_malloc(sizeof(link_t));
  g_assert(link);

  link->link_id = *link_id;

  traffic_stats_init(&link->link_stats);

  return link;
}

/* destroys a link, releasing memory */
void link_delete(link_t *link)
{
  g_assert(link);

  /* first, free any conversation belonging to the link */
  delete_conversation_link(&link->link_id.src.addr.ip,
                           &link->link_id.dst.addr.ip);

  traffic_stats_reset(&link->link_stats);

  g_free(link);
}

gchar *link_dump(const link_t *link)
{
  gchar *msg;
  gchar *msg_idsrc;
  gchar *msg_iddst;
  gchar *msg_stats;
  gchar *msg_mprot;
  const gchar *main_prot;
  guint i;

  if (!link)
    return g_strdup("link_t NULL");

  msg_idsrc = node_id_dump(&link->link_id.src);
  msg_iddst = node_id_dump(&link->link_id.dst);
  msg_stats = traffic_stats_dump(&link->link_stats);

  main_prot = traffic_stats_most_used_proto(&link->link_stats, 0);
  msg_mprot = g_strdup_printf("top: [%s], stack:",
                              (main_prot) ? main_prot : "-none-");

  for (i = 1; i <= STACK_SIZE; i++) {
    gchar *tmp = msg_mprot;
    main_prot = traffic_stats_most_used_proto(&link->link_stats, i);
    msg_mprot = g_strdup_printf("%s %d:>%s<", msg_mprot, i,
                                (main_prot) ? main_prot : "-none-");
    g_free(tmp);
  }

  msg = g_strdup_printf("src: %s, dst: %s, main_prot: [%s], stats [%s]",
                        msg_idsrc, msg_iddst, msg_mprot, msg_stats);
  g_free(msg_idsrc);
  g_free(msg_iddst);
  g_free(msg_stats);
  g_free(msg_mprot);

  return msg;
}

/* returns a newly allocated string with an xml dump of link */
gchar *link_xml(link_t *link)
{
  gchar *msg;
  gchar *msg_id;
  gchar *msg_stats;

  if (!link)
    return xmltag("link", "");

  msg_id = link_id_xml(&link->link_id);
  msg_stats = traffic_stats_xml(&link->link_stats);

  msg = xmltag("link", "\n<link-nodes>\n%s</link-nodes>\n%s",
               msg_id, 
               msg_stats);
  g_free(msg_id);
  g_free(msg_stats);

  return msg;
}

/* gfunc called by g_list_foreach to remove a link */
static void gfunc_remove_link(gpointer data, gpointer user_data)
{
  links_catalog_remove((const link_id_t *)data);
}

static gint update_link(link_id_t *link_id, link_t *link, gpointer delete_list_ptr)
{
  double diffms;

  g_assert(delete_list_ptr);

  /* update stats - returns true if there are active packets */
  if (traffic_stats_update(&link->link_stats, pref.averaging_time,
                           pref.proto_link_timeout_time)) {
    /* packet(s) active, update the most used protocols for this link */
    link_protocol_sort(link);
  }
  else {
    /* no packets remaining on link - if link expiration active, see if the
     * link is expired */
    if (pref.proto_link_timeout_time) {
      diffms = subtract_times_ms(&appdata.now, &link->link_stats.stats.last_time);
      if (diffms >= pref.proto_link_timeout_time) {
        /* link expired, remove */
        GList * *delete_list = (GList * *)delete_list_ptr;

        /* adds current to list of links to delete */
        *delete_list = g_list_prepend(*delete_list, link_id);

        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, _("Queuing link for remove"));
      }
    }
  }

  return FALSE;
}

/* sort protocols by accumulated size */
static void link_protocol_sort(link_t *link)
{
  protocol_stack_sort_most_used(&link->link_stats.stats_protos);
}


/***************************************************************************
 *
 * links catalog implementation
 *
 **************************************************************************/

/* links catalog compare function */
static gint links_catalog_compare(gconstpointer a, gconstpointer b, gpointer dummy)
{
  return link_id_compare((const link_id_t *)a,  (const link_id_t *)b);
}

/* initializes the catalog */
void links_catalog_open(void)
{
  g_assert(!all_links);
  all_links = g_tree_new_full(links_catalog_compare, NULL, NULL,
                              (GDestroyNotify)link_delete);
}

/* closes the catalog, releasing all links */
void links_catalog_close(void)
{
  if (all_links) {
    g_tree_destroy(all_links);
    all_links = NULL;
  }
}

/* insert a new link */
void links_catalog_insert(link_t *new_link)
{
  g_assert(all_links);
  g_assert(new_link);

  g_tree_insert(all_links, &new_link->link_id, new_link);

  if (DEBUG_ENABLED) {
    gchar *str = link_id_node_names(&new_link->link_id);

    g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO,
          _("New link: %s. Number of links %d"),
          str, links_catalog_size());
    g_free(str);
  }
}

/* removes AND DESTROYS the named link from catalog */
void links_catalog_remove(const link_id_t *key)
{
  g_assert(all_links);
  g_assert(key);

  g_tree_remove(all_links, key);
}

/* finds a link */
link_t *links_catalog_find(const link_id_t *key)
{
  g_assert(key);
  if (!all_links)
    return NULL;

  return g_tree_lookup(all_links, key);
}

/* finds a link, creating one if necessary */
link_t *links_catalog_find_create(const link_id_t *key)
{
  link_t *link;
  g_assert(all_links);
  g_assert(key);

  link = links_catalog_find(key);
  if (!link) {
    link = link_create(key);
    links_catalog_insert(link);
  }
  return link;
}

/* returns the current number of links in catalog */
gint links_catalog_size(void)
{
  if (!all_links)
    return 0;

  return g_tree_nnodes(all_links);
}

/* calls the func for every link */
void links_catalog_foreach(GTraverseFunc func, gpointer data)
{
  if (!all_links)
    return;

  return g_tree_foreach(all_links, func, data);
}

/* Calls update_link for every link. This is actually a function that
 shouldn't be called often, because it might take a very long time
 to complete */
void links_catalog_update_all(void)
{
  GList *delete_list = NULL;

  if (!all_links)
    return;

  /* we can't delete links while traversing the catalog, so while updating links
   * we fill a list with the expired link_id's */
  links_catalog_foreach((GTraverseFunc)update_link, &delete_list);

  /* after, remove all links on the list from catalog
   * WARNING: after this call, the list items are also destroyed */
  g_list_foreach(delete_list, gfunc_remove_link, NULL);

  /* free the list - list items are already destroyed */
  g_list_free(delete_list);

  g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        _("Updated links. Active links %d"), links_catalog_size());
}

/* adds a new packet to the link, creating it if necessary */
void links_catalog_add_packet(const link_id_t *link_id, packet_info_t *packet,
                              packet_direction direction)
{
  link_t *link;

  /* retrieves link from catalog, creating a new one if necessary */
  link = links_catalog_find_create(link_id);

  traffic_stats_add_packet(&link->link_stats, packet, direction);
}

static gboolean link_dump_tvs(gpointer key, gpointer value, gpointer data)
{
  gchar *msg_link;
  gchar *tmp;
  gchar * *msg = (gchar * *)data;
  const link_t *link = (const link_t *)value;

  msg_link = link_dump(link);
  tmp = *msg;
  *msg = g_strdup_printf("%slink %p:\n%s\n", tmp, link, msg_link);
  g_free(tmp);
  g_free(msg_link);
  return FALSE;
}

gchar *links_catalog_dump(void)
{
  gchar *msg;

  msg = g_strdup("");
  links_catalog_foreach(link_dump_tvs, &msg);
  return msg;
}

static gboolean link_xml_tvs(gpointer key, gpointer value, gpointer data)
{
  gchar *msg_link;
  gchar *tmp;
  struct xml_tvs_helper *xth = (struct xml_tvs_helper *)data;
  link_t *link = (link_t *)value;

  msg_link = link_xml(link);
  tmp = xth->msg;
  xth->msg = g_strdup_printf("%s%s", tmp, msg_link);
  g_free(tmp);
  g_free(msg_link);
  xth->total_size += link->link_stats.stats.accumulated;
  xth->total_packets += link->link_stats.stats.accu_packets;
  return FALSE;
}

/* returns a newly allocated string with an xml dump of all links */
gchar *links_catalog_xml(void)
{
  gchar *xml;
  struct xml_tvs_helper xth;

  xth.total_size = 0;
  xth.total_packets = 0;
  xth.msg = g_strdup("");

  links_catalog_foreach(link_xml_tvs, &xth);
  xml = xmltag("links", "\n<accumulated>%.0f</accumulated>\n<packets>%lu</packets>\n%s", xth.total_size, xth.total_packets, xth.msg);
  g_free(xth.msg);
  return xml;
}
