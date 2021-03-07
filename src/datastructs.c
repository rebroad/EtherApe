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

#include <glib.h>
#include <gtk/gtk.h>
#include <netdb.h>
#include "datastructs.h"
#include "appdata.h"
#include "stats/util.h"

#define LINESIZE  1024


/************************************************************************
 *
 * services and port_service_t data and functions
 *
 ************************************************************************/
static GTree *service_names = NULL;
static GTree *tcp_services = NULL;
static GTree *udp_services = NULL;
static void services_fill_preferred(void);
static port_service_t *port_service_new(port_type_t port, const gchar *name);
static void port_service_free(port_service_t *);

/************************************************************************
 *
 * proto->color hash table support functions
 *
 ************************************************************************/
static GHashTable *protohash = NULL; /* the hash table containing proto,color pairs*/
static GList *cycle_color_list = NULL; /* the list of colors without protocol */
static GList *current_cycle = NULL; /* current ptr to free color */

/* adds or replaces the protoname item */
static gboolean protohash_set(gchar *protoname, const GdkRGBA *protocolor);

static void freehash(gpointer data)
{
  g_free(data);
}

static gboolean protohash_init(void)
{
  if (protohash)
    return TRUE; /* already ok */

  protohash = g_hash_table_new_full(g_str_hash,
                                    g_str_equal,
                                    freehash,
                                    freehash);
  return protohash != NULL;
}

/* clears the proto hash */
void protohash_clear(void)
{
  if (protohash) {
    g_hash_table_destroy(protohash);
    protohash = NULL;
  }

  while (cycle_color_list) {
    g_free(cycle_color_list->data);
    cycle_color_list = g_list_delete_link(cycle_color_list, cycle_color_list);
  }
  current_cycle = NULL;
}

/* adds or replaces the protoname item */
static gboolean protohash_set(gchar *protoname, const GdkRGBA *protocolor)
{
  ColorHashItem item;

  g_assert(protocolor);
  if (!protohash && !protohash_init())
    return FALSE;

  item.color = *protocolor;

  /* if a protocol is specified, we put the pair (proto,color) in the hash,
   * marking it as preferred (a color obtained from user mappings) */
  if (protoname && *protoname) {
    item.preferred = TRUE;
    g_hash_table_insert(protohash, g_strdup(protoname),
                        g_memdup(&item, sizeof(ColorHashItem)));
  }

  /* Without protocols defined we add the color to the cycle list. Cycle colors
     aren't preferred */
  if (!protoname || !*protoname) {
    item.preferred = FALSE;
    cycle_color_list = g_list_prepend(cycle_color_list,
                                      g_memdup(&item, sizeof(ColorHashItem)));
    current_cycle = cycle_color_list;
  }

  return TRUE;
}

/* resets the cycle color to start of list */
void protohash_reset_cycle(void)
{
  current_cycle = cycle_color_list;
}

/* returns the colorhash item from the named protocol, creating a new entry if
   needed.  Internal use only */
static const ColorHashItem *protohash_itemproto(const gchar *protoname)
{
  const ColorHashItem *item;
  g_assert(protoname); /* proto must be valid - note: empty IS valid, NULL no*/
  g_assert(protohash);

  item = (ColorHashItem *)g_hash_table_lookup(protohash, protoname);
  if (!item) {
    /* color not found, take from cycle list */
    item = (ColorHashItem *)current_cycle->data;

    /* add to hash */
    g_hash_table_insert(protohash, g_strdup(protoname),
                        g_memdup(item, sizeof(ColorHashItem)));

    /* advance cycle */
    current_cycle = current_cycle->next;
    if (!current_cycle)
      current_cycle = cycle_color_list;
  }
/*  g_my_debug ("Protocol %s in color 0x%2.2x%2.2x%2.2x",
              protoname, color->red, color->green, color->blue); */
  return item;
}

const GdkRGBA *protohash_color(const gchar *protoname)
{
  g_assert(protoname); /* proto must be valid - note: empty IS valid, NULL no*/
  g_assert(protohash);
  return &(protohash_itemproto(protoname)->color);
}

/* returns the preferred flag */
gboolean protohash_is_preferred(const gchar *protoname)
{
  const ColorHashItem *item;
  g_assert(protoname); /* proto must be valid - note: empty IS valid, NULL no*/
  g_assert(protohash);

  item = (ColorHashItem *)g_hash_table_lookup(protohash, protoname);
  if (!item)
    return FALSE;

  return item->preferred;
}

/* fills the hash from a pref vector */
gboolean protohash_read_prefvect(gchar * *colors)
{
  int i;
  GdkRGBA color;

  protohash_clear();

  /* fills with colors */
  for (i = 0; colors[i]; ++i) {
    gchar * *colors_protocols, * *protos;
    int j;

    colors_protocols = g_strsplit_set(colors[i], "; \t\n", 0);
    if (!colors_protocols[0])
      continue;

    /* converting color */
    gdk_rgba_parse(&color, colors_protocols[0]);

    if (!colors_protocols[1] || !strlen(colors_protocols[1]))
      protohash_set(colors_protocols[1], &color);
    else {
      /* multiple protos, split them */
      protos = g_strsplit_set(colors_protocols[1], ", \t\n", 0);
      for (j = 0; protos[j]; ++j)
        if (protos[j] && *protos[j])
          protohash_set(protos[j], &color);


      g_strfreev(protos);
    }
    g_strfreev(colors_protocols);
  }

  if (!cycle_color_list) {
    /* the list of color available for unmapped protocols is empty,
     * so we add a grey */
    gdk_rgba_parse(&color, "#7f7f7f");
    protohash_set(NULL, &color);
  }
  else
    cycle_color_list = g_list_reverse(cycle_color_list); /* list was reversed */

  /* update preferred flag on services tree */
  services_fill_preferred();
  return TRUE;
}



/* compacts the array of colors/protocols mappings by collapsing identical
 * colors - frees the input array */
gchar **protohash_compact(gchar * *colors)
{
  int i;
  gchar * *compacted;
  GList *work;
  GList *el;

  /* constructs a list with unique colors. We use a list to maintain the
     fill order of the dialog. This is less surprising for the user. */
  work = NULL;
  for (i = 0; colors[i]; ++i) {
    gchar * *colors_protocols;

    colors_protocols = g_strsplit_set(colors[i], "; \t\n", 0);
    if (!colors_protocols[0])
      continue;

    colors_protocols[1] = remove_spaces(colors_protocols[1]);

    for (el = g_list_first(work); el; el = g_list_next(el)) {
      gchar * *col = (gchar * *)(el->data);
      if (!col || !col[0])
        continue;
      if (!g_ascii_strcasecmp(col[0], colors_protocols[0])) {
        /* found same color, append protocol */
        gchar *old = col[1];
        if (colors_protocols[1] && *colors_protocols[1]) {
          if (old)
            col[1] = g_strjoin(",", old, colors_protocols[1], NULL);
          else
            col[1] = g_strdup(colors_protocols[1]);
          g_free(old);
        }
        break;
      }
    }

    if (el)
      g_strfreev(colors_protocols); /* found, free temporary */
    else {
      /* color not found, adds to list - no need to free here */
      work = g_list_prepend(work, colors_protocols);
    }
  }

  /* reverse list to match original order (with GList, prepend+reverse is more
     efficient than append */
  work = g_list_reverse(work);

  /* now scans the list filling the protostring */
  compacted = malloc(sizeof(gchar *) * (g_list_length(work) + 1));
  i = 0;
  for (el = g_list_first(work); el; el = g_list_next(el)) {
    gchar * *col = (gchar * *)(el->data);
    compacted[i++] = g_strjoin(";", col[0], col[1], NULL);
    g_strfreev(col);
  }
  compacted[i] = NULL;
  g_list_free(work);
  g_strfreev(colors);
  return compacted;
}

/*
 ***********************************************************************
 *
 * compacting function
 *
 ***********************************************************************
*/
gchar *remove_spaces(gchar *str)
{
  char *out = str;
  char *cur = str;
  if (str) {
    for (cur = str; *cur; ++cur)
      if (!g_ascii_isspace((guchar)(*cur)))
        *out++ = *cur;


    *out = '\0';
  }
  return str;
}


/************************************************************************
 *
 * proto name mappers
 *
 ************************************************************************/

/* Comparison function to sort tcp/udp services by port number */
static gint services_port_cmp(gconstpointer a, gconstpointer b, gpointer unused)
{
  port_type_t port_a, port_b;

  port_a = *(port_type_t *)a;
  port_b = *(port_type_t *)b;

  if (port_a > port_b)
    return 1;
  if (port_a < port_b)
    return -1;
  return 0;
}                               /* services_port_cmp */

/* Comparison function to sort service names */
static gint services_name_cmp(gconstpointer a, gconstpointer b, gpointer unused)
{
  return g_ascii_strcasecmp((const gchar *)a, (const gchar *)b);
}

static void services_tree_free(gpointer p)
{
  port_service_free((port_service_t *)p);
}

/* traverse function to map names to ports */
static gboolean services_port_trv(gpointer key, gpointer value, gpointer data)
{
  const port_service_t *svc = (const port_service_t *)value;
  GTree *tree = (GTree *)data;
  port_service_t *new_el;

  new_el = port_service_new(svc->port, svc->name);
  g_tree_replace(tree, new_el->name, new_el);
  return FALSE;
}

/* traverse function to fill preferred field */
static gboolean services_pref_trv(gpointer key, gpointer value, gpointer data)
{
  port_service_t *svc = (port_service_t *)value;
  svc->preferred = protohash_is_preferred(svc->name);
  return FALSE;
}
static void services_fill_preferred(void)
{
  if (udp_services)
    g_tree_foreach(udp_services, services_pref_trv, NULL);
  if (tcp_services)
    g_tree_foreach(tcp_services, services_pref_trv, NULL);
}

void services_init(void)
{
  struct servent *ent;
  port_service_t *port_service;

  g_assert(!service_names && !tcp_services && !udp_services);

  service_names = g_tree_new_full(services_name_cmp, NULL, NULL, services_tree_free);
  tcp_services = g_tree_new_full(services_port_cmp, NULL, NULL, services_tree_free);
  udp_services = g_tree_new_full(services_port_cmp, NULL, NULL, services_tree_free);

  while ((ent = getservent())) {
    if (g_ascii_strcasecmp(ent->s_proto, "tcp") &&
        g_ascii_strcasecmp(ent->s_proto, "udp"))
      g_my_info(_("%s protocol not supported"), ent->s_proto);
    else {
      port_service = port_service_new(ntohs(ent->s_port), ent->s_name);
      g_tree_replace(ent->s_proto[0] == 't' ? tcp_services : udp_services,
                     &port_service->port, port_service);
    }
  }

  endservent();

  /* now traverse port->name trees to fill the name->port tree */
  g_tree_foreach(udp_services, services_port_trv, service_names);
  g_tree_foreach(tcp_services, services_port_trv, service_names);

  /* and finally assign preferred services */
  services_fill_preferred();
}

void services_clear(void)
{
  if (service_names)
    g_tree_destroy(service_names);
  if (tcp_services)
    g_tree_destroy(tcp_services);
  if (udp_services)
    g_tree_destroy(udp_services);
}

const port_service_t *services_tcp_find(port_type_t port)
{
  if (tcp_services)
    return (port_service_t *)g_tree_lookup(tcp_services, &port);
  else
    return NULL;
}

const port_service_t *services_udp_find(port_type_t port)
{
  if (udp_services)
    return (port_service_t *)g_tree_lookup(udp_services, &port);
  else
    return NULL;
}

/************************************************************************
 *
 * port_service_t functions
 *
 ************************************************************************/
port_service_t *port_service_new(port_type_t port, const gchar *name)
{
  port_service_t *p;
  p = g_malloc(sizeof(port_service_t));
  g_assert(p);

  p->port = port;
  p->name = g_ascii_strup(name, -1);
  p->preferred = FALSE;
  return p;
}

void port_service_free(port_service_t *p)
{
  if (p)
    g_free(p->name);
  g_free(p);
}

const port_service_t *services_port_find(const gchar *name)
{
  if (!name || !service_names)
    return NULL;

  return (const port_service_t *)g_tree_lookup(service_names, name);
}
