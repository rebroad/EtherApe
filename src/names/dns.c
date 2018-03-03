/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 *
 * common dns routines
 *
 * Extended for optional libcares support by Zev Weiss, (c) 2016
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include "appdata.h"
#include "dns.h"

#ifdef HAVE_LIBCARES
#include "ares_resolve.h"
#else
#include "thread_resolve.h"
#endif

/* initialize dns interface */
int dns_open(void)
{
#ifdef HAVE_LIBCARES
  return ares_open();
#else   
  return thread_open();
#endif    
}

/* close dns interface */
void dns_close(void)
{
#ifdef HAVE_LIBCARES
  ares_close();
#else   
  thread_close();
#endif    
}

/* resolves address and returns its fqdn */
const char *dns_lookup(address_t *addr)
{
#ifdef HAVE_LIBCARES
  return ares_lookup(addr);
#else   
  return thread_lookup(addr);
#endif    
}

