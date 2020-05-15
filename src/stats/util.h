/* util.h
 * Utility definitions
 *
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

#ifndef __UTIL_H__
#define __UTIL_H__

#include "common.h"

char *safe_strncpy(char *dst, const char *src, size_t maxlen);
char *safe_strncat(char *dst, const char *src, size_t maxlen);

/* utility functions */
const gchar *ipv4_to_str(const guint8 *ad);
const gchar *ether_to_str(const guint8 *ad);
const gchar *ipv6_to_str(const guint8 *ad);
const gchar *address_to_str(const address_t *ad);
const gchar *type_to_str(const address_t *ad);

/*
 * strtol()-like that writes converted value to *val and returns an errno
 * value (0 for success, non-zero for failure)
 */
int strict_strtol(const char *str, int base, long *val);

int bitwise_memcmp(const void *a, const void *b, size_t nbits);

/* returns a newly allocated string with a timeval in human readable form */
gchar *timeval_to_str(struct timeval last_heard);

/* xml helpers */
gchar *xmltag(const gchar *name, const gchar *fmt, ...);

#endif /* __UTIL_H__ */
