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

#ifndef ETHERAPE_COMMON_H
#define ETHERAPE_COMMON_H

/* disable deprecated gnome functions */
/* #define G_DISABLE_DEPRECATED 1 */

#include "config.h"


#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#elif HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <glib.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#ifndef _
#define _(String)  gettext(String)
#endif
#else
#ifndef _
#define _(String)  (String)
#endif
#endif

#ifndef MAXDNAME
#define MAXDNAME  1025          /* maximum domain name length */
#endif

typedef enum
{
  /* Beware! The value given by the option widget is dependant on
   * the order set in glade! */
  LINEAR = 0,
  LOG = 1,
  SQRT = 2
} size_mode_t;

typedef enum
{
  /* Beware! The value given by the option widget must be coherent with
   * the order of string in glade combo! */
  INST_TOTAL = 0,
  INST_INBOUND,
  INST_OUTBOUND,
  INST_PACKETS,
  ACCU_TOTAL,
  ACCU_INBOUND,
  ACCU_OUTBOUND,
  ACCU_PACKETS,
  ACCU_AVG_SIZE,
} node_size_variable_t;

typedef enum
{
  APEMODE_DEFAULT = -1,
  LINK6 = 0,        /* data link level with 6 bits of address */
  IP,
  TCP
} apemode_t;

typedef enum
{
  /* Beware! The value given by the option widget must be coherent with
   * the order of string in glade combo! */
  STATSPOS_NONE = 0,
  STATSPOS_UPPER_LEFT = 1,
  STATSPOS_UPPER_RIGHT = 2,
  STATSPOS_LOWER_LEFT = 3,
  STATSPOS_LOWER_RIGHT = 4,
} statspos_t;

typedef struct __attribute__ ((packed))
{
  union __attribute__ ((packed))
  {
    struct __attribute__ ((packed))
    {
      guint32 type; /* address family: AF_INET or AF_INET6 */
      union __attribute__ ((packed))
      {
        guint8 addr8[16];   /* 128-bit */
        guint8 addr_v4[4];  /* 32-bit  */
        guint8 addr_v6[16]; /* 128-bit */
      };
    };
    guint8 all8[4*5];
  };
}
address_t;

/* Macros */
#define address_copy(dst, src)  memmove((dst), (src), sizeof(address_t))
#define address_clear(dst)      memset((dst), 0, sizeof(address_t))
#define address_len(type)       ((type) == AF_INET ? 32/8 : (type) == AF_INET6 ? 128/8 : 0)
#define is_addr_eq(dst, src)    (memcmp((dst), (src), sizeof(address_t)) == 0)
#define is_addr_gt(dst, src)    (memcmp((dst), (src), sizeof(address_t)) > 0)
#define is_addr_lt(dst, src)    (memcmp((dst), (src), sizeof(address_t)) < 0)
#define is_addr_ge(dst, src)    (memcmp((dst), (src), sizeof(address_t)) >= 0)
#define is_addr_le(dst, src)    (memcmp((dst), (src), sizeof(address_t)) <= 0)

static inline int address_cmp(const address_t *a, const address_t *b)
{
  if (a->type != b->type)
    return a->type - b->type;
  else
    return memcmp(a->addr8, b->addr8, address_len(a->type));
}

#define g_my_debug(format, args ...)     g_log(G_LOG_DOMAIN, \
                                               G_LOG_LEVEL_DEBUG, \
                                               format, ## args)
#define g_my_info(format, args ...)      g_log(G_LOG_DOMAIN, \
                                               G_LOG_LEVEL_INFO, \
                                               format, ## args)
#define g_my_critical(format, args ...)  g_log(G_LOG_DOMAIN, \
                                               G_LOG_LEVEL_CRITICAL, \
                                               format, ## args)

/*
 * Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 */
#define MAKE_PNxH(direction, suffix, type) \
  static inline type p ## direction ## suffix(const void *p) \
  { \
    type tmp; \
    memcpy(&tmp, p, sizeof(tmp)); \
    return direction ## suffix(tmp); \
  }

MAKE_PNxH(hton, s, guint16);
MAKE_PNxH(ntoh, s, guint16);
MAKE_PNxH(hton, l, guint32);
MAKE_PNxH(ntoh, l, guint32);

/* Takes the hi_nibble value from a byte */
#define hi_nibble(b)  ((b & 0xf0) >> 4)

#endif /* ETHERAPE_COMMON_H */
