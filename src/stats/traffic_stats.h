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

#ifndef TRAFFIC_STATS_H
#define TRAFFIC_STATS_H

#include <sys/time.h>
#include "protocols.h"

typedef struct
{
  GQueue pkt_list;              /* list of packet_list_item_t - private */
  basic_stats_t stats;        /* total traffic stats */
  basic_stats_t stats_in;     /* inbound traffic stats */
  basic_stats_t stats_out;    /* outbound traffic stats */
  protostack_t stats_protos;    /* protocol stack */
} traffic_stats_t;

void traffic_stats_init(traffic_stats_t *pkt_stat); /* initializes counters */
void traffic_stats_reset(traffic_stats_t *pkt_stat); /* releases memory */
/* adds another item stats to current element stats - doesn't copies packets! */
void traffic_stats_sum(traffic_stats_t *pkt_stat, const traffic_stats_t *tosum);
void traffic_stats_add_packet(traffic_stats_t *pkt_stat,
                              packet_info_t *new_pkt,
                              packet_direction dir); /* adds a packet */
void traffic_stats_calc_averages(traffic_stats_t *pkt_stat, double avg_time); 
/* purges expired packets and recalc averages */
gboolean traffic_stats_update(traffic_stats_t *pkt_stat, double pkt_expire_time, double proto_expire_time);
/* returns the name of most used protocol at the specified level, if present (NULL otherwise) */
const gchar *traffic_stats_most_used_proto(const traffic_stats_t *pkt_stat, size_t level);

gchar *traffic_stats_dump(const traffic_stats_t *pkt_stat);
gchar *traffic_stats_xml(const traffic_stats_t *pkt_stat);

#endif
