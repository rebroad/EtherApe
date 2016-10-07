/* This is pretty messy because it is pretty much copied as is from 
 * ethereal. I should probably clean it up some day */


/* util.c
 * Utility routines
 *
 * Original file by Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * Later changes copyright 2016 Riccardo Ghetta
 *
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

#include <glib.h>
#include <common.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_INET_NTOP
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#elif !defined(INET6_ADDRSTRLEN)
#define INET6_ADDRSTRLEN        46
#endif
#include <locale.h>

#include "appdata.h"
#include "util.h"
#include "traffic_stats.h"


/* safe strncpy */
char *
safe_strncpy (char *dst, const char *src, size_t maxlen)
{
  
if (maxlen < 1)
    return dst;
  strncpy (dst, src, maxlen - 1);	/* no need to copy that last char */
  dst[maxlen - 1] = '\0';
  return dst;
}

/* safe strncat */
char *
safe_strncat (char *dst, const char *src, size_t maxlen)
{
  size_t lendst = strlen (dst);
  if (lendst >= maxlen)
    return dst;			/* already full, nothing to do */
  strncat (dst, src, maxlen - strlen (dst));
  dst[maxlen - 1] = '\0';
  return dst;
}

/* Next three functions copied directly from ethereal packet.c
 * by Gerald Combs */

/* Output has to be copied elsewhere */
const gchar *
ipv4_to_str (const guint8 * ad)
{
#ifdef HAVE_INET_NTOP
  static char buf[INET6_ADDRSTRLEN];
  if (!inet_ntop(AF_INET, ad, buf, sizeof(buf)))
    return "<invalid IPv4 address>";
  return buf;
#else
  static gchar str[3][16];
  static gchar *cur;
  gchar *p;
  int i;
  guint32 octet;
  guint32 digit;

  if (cur == &str[0][0])
    {
      cur = &str[1][0];
    }
  else if (cur == &str[1][0])
    {
      cur = &str[2][0];
    }
  else
    {
      cur = &str[0][0];
    }
  p = &cur[16];
  *--p = '\0';
  i = 3;
  for (;;)
    {
      octet = ad[i];
      *--p = (octet % 10) + '0';
      octet /= 10;
      digit = octet % 10;
      octet /= 10;
      if (digit != 0 || octet != 0)
	*--p = digit + '0';
      if (octet != 0)
	*--p = octet + '0';
      if (i == 0)
	break;
      *--p = '.';
      i--;
    }
  return p;
#endif
}				/* ipv4_to_str */

/* (toledo) This function I copied from capture.c of ethereal it was
 * without comments, but I believe it keeps three different
 * strings conversions in memory so as to try to make sure that
 * the conversions made will be valid in memory for a longer
 * period of time */

/* Places char punct in the string as the hex-digit separator.
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is 5 bytes shorter)
 */

static const gchar *
ether_to_str_punct (const guint8 * ad, char punct)
{
  static gchar str[3][18];
  static gchar *cur;
  gchar *p;
  int i;
  guint32 octet;
  static const gchar hex_digits[16] = "0123456789abcdef";

  if (cur == &str[0][0])
    {
      cur = &str[1][0];
    }
  else if (cur == &str[1][0])
    {
      cur = &str[2][0];
    }
  else
    {
      cur = &str[0][0];
    }
  p = &cur[18];
  *--p = '\0';
  i = 5;
  for (;;)
    {
      octet = ad[i];
      *--p = hex_digits[octet & 0xF];
      octet >>= 4;
      *--p = hex_digits[octet & 0xF];
      if (i == 0)
	break;
      if (punct)
	*--p = punct;
      i--;
    }
  return p;
}				/* ether_to_str_punct */

/* Wrapper for the most common case of asking
 * for a string using a colon as the hex-digit separator.
 */
const gchar *
ether_to_str (const guint8 * ad)
{
  return ether_to_str_punct (ad, ':');
}				/* ether_to_str */

/*
 * These functions are for IP/IPv6 handling
 */
const gchar *ipv6_to_str (const guint8 *ad)
{
  if (!ad)
    return "<null addr>";
#ifdef HAVE_INET_NTOP
  static char buf[INET6_ADDRSTRLEN];
  if (!inet_ntop(AF_INET6, ad, buf, sizeof(buf))) 
    return "<invalid IPv6 address>";
  return buf;
#else
  static gchar str[3][40];
  static gchar *cur;
  gchar *p;
  int i;
  guint32 octet;
  static const gchar hex_digits[16] = "0123456789abcdef";

  if (cur == &str[0][0])
    {
      cur = &str[1][0];
    }
  else if (cur == &str[1][0])
    {
      cur = &str[2][0];
    }
  else
    {
      cur = &str[0][0];
    }
  p = &cur[40];
  *--p = '\0';
  i = 15;
  for (;;)
    {
      octet = ad[i];
      *--p = hex_digits[octet & 0xF];
      octet >>= 4;
      *--p = hex_digits[octet & 0xF];
      i--;
      octet = ad[i];
      *--p = hex_digits[octet & 0xF];
      octet >>= 4;
      *--p = hex_digits[octet & 0xF];
      if (i == 0)
    break;
	  *--p = ':';
      i--;
    }
  return p;
#endif
}				/* ipv6_to_str */

const gchar *
address_to_str (const address_t * ad)
{
  if (!ad)
    return "<null addr>";
  switch (ad->type)
    {
    case AF_INET:
      return ipv4_to_str(ad->addr_v4);
    case AF_INET6:
      return ipv6_to_str(ad->addr_v6);
    default:
      return "<invalid address family>";
    }
}				/* address_to_str */

const gchar *
type_to_str (const address_t * ad)
{
  if (!ad)
    return "<null addr>";
  switch (ad->type)
    {
    case AF_INET:
      return "IP";
    case AF_INET6:
      return "IPv6";
    default:
      return "<invalid address family>";
    }
}				/* type_to_str */

int
strict_strtol(const char *str, int base, long *val)
{
  char *end;
  *val = strtol(str, &end, base);
  return (*str && !*end) ? 0 : EINVAL;
}

/* Like memcp(3), but bitwise (big-endian at the sub-byte level) */
int bitwise_memcmp(const void *a, const void *b, size_t nbits)
{
  int ret;
  unsigned char a_last, b_last, mask;
  size_t wholebytes = nbits / CHAR_BIT, rembits = nbits % CHAR_BIT;

  ret = memcmp(a, b, wholebytes);
  if (ret)
    return ret;

  mask = ~(rembits ? (1 << (CHAR_BIT - rembits)) - 1 : 0xFF);
  a_last = *((unsigned char*)a + wholebytes) & mask;
  b_last = *((unsigned char*)b + wholebytes) & mask;

  return a_last - b_last;
}

/* returns a newly allocated string with a timeval in human readable form */
gchar *timeval_to_str(struct timeval last_heard)
{
  gchar *str;
  struct timeval diff;
  struct tm broken_time;

  diff = subtract_times(appdata.now, last_heard);
  if (diff.tv_sec <= 60)
    {
      /* Meaning "n seconds" ago */
      return g_strdup_printf (_("%ld\" ago"), (long) diff.tv_sec);
    }

  if (diff.tv_sec < 600)
    {
      /* Meaning "m minutes, n seconds ago" */
      return g_strdup_printf (_("%ld'%ld\" ago"),
			 (long) floor ((double) diff.tv_sec / 60),
			 (long) diff.tv_sec % 60);
    }

  if (!localtime_r ((time_t *) & (last_heard.tv_sec), &broken_time))
    {
      g_my_critical ("Time conversion failed in timeval_to_str");
      return NULL;
    }

  if (diff.tv_sec < 3600 * 24)
      str = g_strdup_printf ("%d:%d", broken_time.tm_hour, broken_time.tm_min);
  else
    {
      /* Watch out! The first is month, the second day of the month */
      str = g_strdup_printf (_("%d/%d %d:%d"),
			     broken_time.tm_mon, broken_time.tm_mday,
			     broken_time.tm_hour, broken_time.tm_min);
    }

  return str;
}				/* timeval_to_str */


/************************************************
 *
 * xml helpers 
 *
 *************************************************/

/* returns a new string containing the named tag */
gchar *xmltag(const gchar *name, const gchar *fmt, ...)
{
  gchar *msg;
  gchar *xml;
  va_list ap;
  va_start(ap, fmt);
  msg = g_strdup_vprintf(fmt, ap);
  va_end(ap);
  xml = g_strdup_printf("<%s>%s</%s>\n", name, msg, name);
  g_free(msg);
  return xml;
}


