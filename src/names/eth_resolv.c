/*
 * Translate ethernet address to IPs/hostnames via /etc/ethers
 *
 * Copyright (C) 2014 Zev Weiss <zev@bewilderbeest.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/ether.h>

#include <glib.h>

#define EPATH_ETHERS  "/etc/ethers"

#define ETHBUFSIZE  4096

static GTree *ethers;

struct ether_ent
{
  struct ether_addr addr;
  char hostname[];
};

static int ether_tree_cmp(gconstpointer ga, gconstpointer gb, gpointer unused)
{
  const struct ether_addr *a = ga;
  const struct ether_addr *b = gb;

  return memcmp(&a->ether_addr_octet, &b->ether_addr_octet,
                sizeof(a->ether_addr_octet));
}

static void add_ether_ent(const struct ether_addr *addr, const char *hostname)
{
  struct ether_ent *ent = g_malloc(sizeof(*ent) + strlen(hostname) + 1);
  ent->addr = *addr;
  strcpy(ent->hostname, hostname);
  g_tree_insert(ethers, &ent->addr, ent);
}

void init_eth_resolv(void)
{
  FILE *ethf;
  size_t linelen;
  int c;
  char ethline[ETHBUFSIZE];
  /*
   * This being as large as ethline is important to guarantee ether_line
   * doesn't overflow it.  Lines longer than ETHBUFSIZE are simply rejected.
   */
  char hostname[ETHBUFSIZE];
  struct ether_addr addr;

  ethers = g_tree_new_full(ether_tree_cmp, NULL, NULL, g_free);

  ethf = fopen(EPATH_ETHERS, "r");
  if (!ethf)
    return;

  for (;;) {
    if (!fgets(ethline, sizeof(ethline), ethf))
      break;

    linelen = strlen(ethline);
    if (linelen == sizeof(ethline) - 1 && ethline[linelen-1] != '\n') {
      ethline[17] = '\0';
      g_warning("Ignoring stupidly long %s line starting \"%s...\"",
                EPATH_ETHERS, ethline);
      /* Discard the remainder of the line */
      while ((c = fgetc(ethf)) != '\n') {
        if (c == EOF)
          break;
      }
    }

    if (!ether_line(ethline, &addr, hostname))
      add_ether_ent(&addr, hostname);
  }

  fclose(ethf);
  return;
}

void cleanup_eth_resolv(void)
{
  g_tree_destroy(ethers);
  ethers = NULL;
}

const char *get_ether_name(const unsigned char *addr_bytes)
{
  struct ether_addr addr;
  struct ether_ent *ent;
  size_t addrstr_size;

  memcpy(&addr.ether_addr_octet, addr_bytes, sizeof(addr.ether_addr_octet));

  ent = g_tree_lookup(ethers, &addr);
  if (ent)
    return ent->hostname;

  /* Otherwise we'll record a new entry for this address */
  addrstr_size = strlen("XX:XX:XX:XX:XX:XX")+1;
  ent = g_malloc(sizeof(*ent) + addrstr_size);
  ent->addr = addr;
  snprintf(ent->hostname, addrstr_size, "%02x:%02x:%02x:%02x:%02x:%02x",
           addr.ether_addr_octet[0], addr.ether_addr_octet[1],
           addr.ether_addr_octet[2], addr.ether_addr_octet[3],
           addr.ether_addr_octet[4], addr.ether_addr_octet[5]);
  g_tree_insert(ethers, &ent->addr, ent);
  return ent->hostname;
}
