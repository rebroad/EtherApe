/*
   $Id$

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   ----------------------------------------------------------------

   A simple cache of ipaddr->hostname lookups.  The cache is pruned
   periodically, removing entries whose expiry times have passed.  Negative
   caching is also performed.

   Copyright (C) 2014 Zev Weiss <zev@bewilderbeest.net>
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "common.h"
#include "preferences.h"
#include "stats/util.h"
#include "ip-cache.h"

static GTree *ipcache_tree = NULL;

static int addr_tree_cmp(gconstpointer a, gconstpointer b, gpointer unused)
{
  return address_cmp(a, b);
}

struct prune_ctx
{
  time_t now;
  GSList *to_free;
};

static gboolean find_expired(gpointer key, gpointer value, gpointer data)
{
  struct ipcache_item *item = value;
  struct prune_ctx *ctx = data;

  /* Don't prune items that are still being resolved */
  if (item && item->expiry != 0 && item->state != ICS_RESOLVING && item->expiry < ctx->now)
    ctx->to_free = g_slist_prepend(ctx->to_free, item);

  return FALSE; /* don't terminate traversal */
}

static void del_expired(gpointer data, gpointer unused)
{
  struct ipcache_item *item = data;
  gboolean found = g_tree_remove(ipcache_tree, &item->ip);
  g_assert(found);
}

static gboolean ipcache_prune(gpointer data)
{
  struct prune_ctx ctx = {
    .now = time(NULL), .to_free = NULL,
  };

  if (ipcache_tree) {
    g_tree_foreach(ipcache_tree, find_expired, &ctx);

    g_slist_foreach(ctx.to_free, del_expired, NULL);
    g_slist_free(ctx.to_free);
  }
  return TRUE;
}

static void free_ipcache_item(gpointer data)
{
  struct ipcache_item *item = data;
  g_free(item->hostname);
  g_free(item);
}

void ipcache_init(void)
{
  g_timeout_add_seconds(10, ipcache_prune, NULL);
  ipcache_tree = g_tree_new_full(addr_tree_cmp, NULL, NULL, free_ipcache_item);
}

void ipcache_clear(void)
{
  if (ipcache_tree)
    g_tree_destroy(ipcache_tree);
  ipcache_tree = NULL;
}

long ipcache_active_entries(void)
{
  if (!ipcache_tree)
    return 0;
  return g_tree_nnodes(ipcache_tree);
}

const char *ipcache_lookup(const address_t *addr)
{
  struct ipcache_item *item;

  if (!pref.name_res)
    return address_to_str(addr); /* name resolution globally disabled */

  if (!ipcache_tree)
    return NULL;

  item = g_tree_lookup(ipcache_tree, addr);
  if (item) {
    if (item->state == ICS_RESOLVED)
      return item->hostname;
    else
      return address_to_str(&item->ip);
  }
  else
    return NULL;
}

static struct ipcache_item *ipcache_alloc_item(const address_t *ip)
{
  struct ipcache_item *item;

  item = g_malloc0(sizeof(*item));

  item->state = ICS_RESOLVING;
  address_copy(&item->ip, ip);

  return item;
}

struct ipcache_item *ipcache_prepare_request(const address_t *ip)
{
  struct ipcache_item *item;

  g_assert(ip);

  item = g_tree_lookup(ipcache_tree, ip);
  g_assert(!item);
  item = ipcache_alloc_item(ip);

  g_tree_insert(ipcache_tree, &item->ip, item);

  return item;
}

void ipcache_request_succeeded(struct ipcache_item *rp, long ttl, const char *ipname)
{
  rp->hostname = g_strdup(ipname);
  rp->expiry = time(NULL) + ttl;
  rp->state = ICS_RESOLVED;
}

void ipcache_request_failed(struct ipcache_item *rp)
{
  /* Arbitrary default negative cache timeout of 5 minutes */
  rp->expiry = time(NULL) + 300;
  rp->state = ICS_FAILED;
}
