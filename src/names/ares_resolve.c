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
 * optional libcares support by Zev Weiss, (c) 2016
 */

#ifdef HAVE_CONFIG_H
#include "../../config.h"
#endif

#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <pthread.h>
#include <ares.h>

#include "appdata.h"
#include "dns.h"

#include "ip-cache.h"
#include "stats/util.h"


static ares_channel ares_chan;
static pthread_t dns_thread;
static pthread_mutex_t dns_mtx;
static pthread_cond_t dns_cond;
/* Used to signal the background thread to stop. */
static int stop_pipe[2];
static int should_stop = 0;

/* Adapted from the example in ares_process(3) */
static void *dns_threadfn(void *arg)
{
  int nfds, count;
  fd_set readfds, writefds;
  struct timeval tv, *tvp;

  /* We release the the lock when waiting on the condvar or select(2)ing. */
  pthread_mutex_lock(&dns_mtx);

  for (;;)
    {
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);

      while ((nfds = ares_fds(ares_chan, &readfds, &writefds)) == 0
             && !should_stop)
        pthread_cond_wait(&dns_cond, &dns_mtx);

      if (should_stop)
        break;

      FD_SET(stop_pipe[0], &readfds);

      tvp = ares_timeout(ares_chan, NULL, &tv);

      pthread_mutex_unlock(&dns_mtx);
      count = select(nfds, &readfds, &writefds, NULL, tvp);
      pthread_mutex_lock(&dns_mtx);

      if (FD_ISSET(stop_pipe[0], &readfds))
        break;

      if (count >= 0)
        ares_process(ares_chan, &readfds, &writefds);
      else
        g_warning("select(2) failed: %s", strerror(errno));
    }

  pthread_mutex_unlock(&dns_mtx);

  close(stop_pipe[0]);

  return NULL;
}

/* initialize dns interface */
int ares_open(void)
{
  ipcache_init();
  /* TODO: check ares_init_options() */
  return ares_library_init(ARES_LIB_INIT_ALL)
    || (ares_init(&ares_chan) != ARES_SUCCESS)
    || pipe(stop_pipe)
    || pthread_cond_init(&dns_cond, NULL)
    || pthread_mutex_init(&dns_mtx, NULL)
    || pthread_create(&dns_thread, NULL, dns_threadfn, NULL);
}

/* close dns interface */
void ares_close(void)
{
  pthread_mutex_lock(&dns_mtx);
  should_stop = 1;
  close(stop_pipe[1]);
  pthread_cond_signal(&dns_cond);
  pthread_mutex_unlock(&dns_mtx);

  pthread_join(dns_thread, NULL);
  pthread_mutex_destroy(&dns_mtx);
  pthread_cond_destroy(&dns_cond);

  ares_destroy(ares_chan);
  ares_library_cleanup();
}

static void rdns_ares_cb(void *arg, int status, int timeouts, struct hostent *hostent)
{
  struct ipcache_item *item = arg;

  switch (status)
    {
    case ARES_SUCCESS:
      /* insert into cache */
      ipcache_request_succeeded(item, 3600, hostent->h_name);
      break;

      /*
       * ARES_ENODATA isn't documented as a possible status for
       * ares_gethostbyaddr(3), but empirically it appears to be popping up.
       * We'll treat it as equivalent to ARES_NOTFOUND.
       */
    case ARES_ENODATA:
    case ARES_ENOTFOUND:
      /* NXDOMAIN */
      ipcache_request_failed(item);
      break;

    case ARES_EDESTRUCTION:
    case ARES_ECANCELLED:
      break;

    case ARES_ENOMEM:
      g_critical("no memory for RDNS lookup");
      break;

    case ARES_ENOTIMP:
      g_error("invalid ares addr type?");
      break;

    default:
      g_warning("unknown ares status: %d\n", status);
      break;
    }
}

static void rdns_request(address_t *addr)
{
  struct ipcache_item *item = ipcache_prepare_request(addr);

  ares_gethostbyaddr(ares_chan, &addr->addr8, address_len(addr->type), addr->type,
                     rdns_ares_cb, item);

  pthread_cond_signal(&dns_cond);
}

/* resolves address and returns its fqdn */
const char *ares_lookup(address_t *addr)
{
  const char *ipname;

  if (!addr)
    return "";

  pthread_mutex_lock(&dns_mtx);

  /* check cache */
  ipname = ipcache_lookup(addr);

  if (!ipname)
    {
      rdns_request(addr);
      ipname = address_to_str(addr);
    }

  pthread_mutex_unlock(&dns_mtx);

  return ipname;
}

