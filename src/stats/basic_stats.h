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

#ifndef BASIC_STATS_H
#define BASIC_STATS_H

#include "../common.h"
#include "pkt_info.h"

/* Returns a timeval structure with the time difference between to
 * other timevals. result = a - b */
struct timeval subtract_times(struct timeval a, struct timeval b);

/* returns the time difference a-b expressed in ms */
double subtract_times_ms(const struct timeval *a, const struct timeval *b);

typedef struct
{
  gdouble average;              /* Average bytes in or out in the last x ms */
  gdouble aver_accu;            /* total bytes of active packets */
  gdouble accumulated;          /* Accumulated bytes */
  gdouble avg_size;              /* average packet size */
  unsigned long accu_packets;   /* Accumulated number of packets */
  struct timeval last_time;     /* Timestamp of the last packet added */
} basic_stats_t;

void basic_stats_reset(basic_stats_t *tf_stat); /* resets counters */
void basic_stats_sum(basic_stats_t *tf_stat, const basic_stats_t *tosum); /* accumulate another basic_stats */
void basic_stats_add(basic_stats_t *tf_stat, gdouble val);
void basic_stats_sub(basic_stats_t *tf_stat, gdouble val);
void basic_stats_avg(basic_stats_t *tf_stat, gdouble avg_msecs);  /* average size and byte rate */
gchar *basic_stats_dump(const basic_stats_t *tf_stat);
gchar *basic_stats_xml(const basic_stats_t *tf_stat);

#endif
