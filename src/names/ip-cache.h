/*
   Etherape
   Copyright (C) 2000 Juan Toledo, Riccardo Ghetta

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

   ip-caching routines
*/

/*  Prototypes for ip-cache.c  */

#ifndef IP_CACHE_H
#define IP_CACHE_H

typedef enum
{
  ICS_RESOLVED,  /* Successfully resolved */
  ICS_RESOLVING, /* Currently being resolved */
  ICS_FAILED,    /* Resolution failed (e.g. NXDOMAIN) */
} ipcache_state_t;

struct ipcache_item
{
  address_t ip;                      /* the IP address this entry caches */
  char *hostname;        /* hostname 'ip' resolved to */
  ipcache_state_t state; /* state of this entry */
  time_t expiry;         /* when this entry expires */
};

void ipcache_init(void);
void ipcache_clear(void);

long ipcache_active_entries(void);

const char *ipcache_lookup(const address_t *addr);
struct ipcache_item *ipcache_prepare_request(const address_t *ip);
void ipcache_request_succeeded(struct ipcache_item *rp, long ttl, const char *ipname);
void ipcache_request_failed(struct ipcache_item *rp);

#endif
