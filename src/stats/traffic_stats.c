/* EtherApe
 * Copyright (C) 2001 Juan Toledo, 2005 Riccardo Ghetta
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appdata.h"
#include "traffic_stats.h"
#include "ui_utils.h"
#include "util.h"
#include "compat.h"

/***************************************************************************
 *
 * traffic_stats_t implementation
 *
 **************************************************************************/

/* initializes counters */
void traffic_stats_init(traffic_stats_t *pkt_stat)
{
  g_assert(pkt_stat);

  g_queue_init(&pkt_stat->pkt_list);

  basic_stats_reset(&pkt_stat->stats);
  basic_stats_reset(&pkt_stat->stats_in);
  basic_stats_reset(&pkt_stat->stats_out);

  protocol_stack_open(&pkt_stat->stats_protos);
}

/* releases memory */
void traffic_stats_reset(traffic_stats_t *pkt_stat)
{
  gpointer it;

  g_assert(pkt_stat);

  /* release items and free list */
  while ((it = g_queue_pop_head(&pkt_stat->pkt_list)) != NULL)
    packet_list_item_delete((packet_list_item_t *)it);

  /* purges protos */
  protocol_stack_reset(&pkt_stat->stats_protos);

  basic_stats_reset(&pkt_stat->stats);
  basic_stats_reset(&pkt_stat->stats_in);
  basic_stats_reset(&pkt_stat->stats_out);
}

/* adds another item stats to current element stats - doesn't copies packets! */
void traffic_stats_sum(traffic_stats_t *pkt_stat, const traffic_stats_t *tosum)
{
  g_assert(pkt_stat);
  g_assert(tosum);

  basic_stats_sum(&pkt_stat->stats, &tosum->stats);
  basic_stats_sum(&pkt_stat->stats_in, &tosum->stats_in);
  basic_stats_sum(&pkt_stat->stats_out, &tosum->stats_out);

  /* adds also to protocol stack */
  protocol_stack_sum(&pkt_stat->stats_protos, &tosum->stats_protos);

  /* note: averages are calculated later, by update_packet_list */
}

/* adds a packet */
void traffic_stats_add_packet(traffic_stats_t *pkt_stat,
                              packet_info_t *new_pkt,
                              packet_direction dir)
{
  packet_list_item_t *newit;

  g_assert(pkt_stat);
  g_assert(new_pkt);

  /* creates a new item, incrementing refcount of new_pkt */
  newit = packet_list_item_create(new_pkt, dir);

  /* adds to list */
  g_queue_push_head(&pkt_stat->pkt_list, newit);

  basic_stats_add(&pkt_stat->stats, newit->info->size);
  if (newit->direction != OUTBOUND)
    basic_stats_add(&pkt_stat->stats_in, newit->info->size); /* in or either */
  if (newit->direction != INBOUND)
    basic_stats_add(&pkt_stat->stats_out, newit->info->size); /* out or either */

  /* adds also to protocol stack */
  protocol_stack_add_pkt(&pkt_stat->stats_protos, newit->info);

  /* note: averages are calculated later, by update_packet_list */
}

static gboolean traffic_stats_purge_expired_packets(traffic_stats_t *pkt_stat, double pkt_expire_time, double proto_expire_time)
{
  double diffms;
  packet_list_item_t *packet;

  /* pkt queue is ordered by arrival time, so older pkts are at tail */
  while (pkt_stat->pkt_list.head) {
    packet = (packet_list_item_t *)g_queue_peek_tail(&pkt_stat->pkt_list);
    diffms = subtract_times_ms(&appdata.now, &packet->info->timestamp);
    if (diffms < pkt_expire_time)
      break; /* packet valid, subsequent packets are younger, no need to go further */

    /* packet expired, remove from stats */
    basic_stats_sub(&pkt_stat->stats, packet->info->size);
    if (packet->direction != OUTBOUND)
      basic_stats_sub(&pkt_stat->stats_in, packet->info->size); /* in or either */
    if (packet->direction != INBOUND)
      basic_stats_sub(&pkt_stat->stats_out, packet->info->size); /* out or either */

    /* and protocol stack */
    protocol_stack_sub_pkt(&pkt_stat->stats_protos, packet->info);

    /* and, finally, from packet queue */
    g_queue_pop_tail(&pkt_stat->pkt_list);
    packet_list_item_delete(packet);
  }

  /* purge expired protocols */
  protocol_stack_purge_expired(&pkt_stat->stats_protos, proto_expire_time);

  if (pkt_stat->pkt_list.head == NULL) {
    /* removed all packets */
    pkt_stat->stats.average = 0;
    pkt_stat->stats_in.average = 0;
    pkt_stat->stats_out.average = 0;
    return FALSE;
  }

  return TRUE;  /* packet list not empty */
}


/* recalculate averages */
void traffic_stats_calc_averages(traffic_stats_t *pkt_stat, double avg_time)
{
  basic_stats_avg(&pkt_stat->stats, avg_time);
  basic_stats_avg(&pkt_stat->stats_in, avg_time);
  basic_stats_avg(&pkt_stat->stats_out, avg_time);
  protocol_stack_avg(&pkt_stat->stats_protos, avg_time);
}

/* Update stats, purging expired packets - returns FALSE if there are no
 * active packets */
gboolean traffic_stats_update(traffic_stats_t *pkt_stat, double avg_time, double proto_expire_time)
{
  gdouble ms_from_oldest = avg_time;
  g_assert(pkt_stat);

  if (!traffic_stats_purge_expired_packets(pkt_stat, avg_time, proto_expire_time)) {
    traffic_stats_calc_averages(pkt_stat, ms_from_oldest);
    return FALSE;   /* no packets remaining */
  }

#if CHECK_EXPIRATION
  /* the last packet of the list is the oldest */
  const packet_list_item_t *packet;
  packet = (const packet_list_item_t *)g_queue_peek_tail(&pkt_stat->pkt_list);
  ms_from_oldest = subtract_times_ms(&now, &packet->info->timestamp);
  if (ms_from_oldest < avg_time)
    ms_from_oldest = avg_time;
  else
    g_warning("ms_to_oldest > avg_time: %f", ms_from_oldest);
#endif

  traffic_stats_calc_averages(pkt_stat, ms_from_oldest);
  return TRUE;   /* there are packets */
}

/* returns the name of most used protocol at the specified level, if present (NULL otherwise) */
const gchar *traffic_stats_most_used_proto(const traffic_stats_t *pkt_stat, size_t level)
{
  if (!pkt_stat)
      return NULL;
  return protocol_stack_most_used(&pkt_stat->stats_protos, level);
}

/* returns a newly allocated string with a dump of pkt_stat */
gchar *traffic_stats_dump(const traffic_stats_t *pkt_stat)
{
  gchar *msg;
  gchar *msg_tot, *msg_in, *msg_out;
  gchar *msg_proto;

  if (!pkt_stat)
    return g_strdup("traffic_stats_t NULL");

  msg_tot = basic_stats_dump(&pkt_stat->stats);
  msg_in = basic_stats_dump(&pkt_stat->stats_in);
  msg_out = basic_stats_dump(&pkt_stat->stats_out);
  msg_proto = protocol_stack_dump(&pkt_stat->stats_protos);
  msg = g_strdup_printf("active_packets: %u\n"
                        "  in : [%s]\n"
                        "  out: [%s]\n"
                        "  tot: [%s]\n"
                        "  protocols:\n"
                        "  %s",
                        pkt_stat->pkt_list.length,
                        msg_in, msg_out, msg_tot, msg_proto);
  g_free(msg_tot);
  g_free(msg_in);
  g_free(msg_out);
  g_free(msg_proto);
  return msg;
}

/* returns a newly allocated string with an xml dump of pkt_stat */
gchar *traffic_stats_xml(const traffic_stats_t *pkt_stat)
{
  gchar *msg;
  gchar *msg_tot, *msg_in, *msg_out;
  gchar *msg_proto;

  if (!pkt_stat)
    return xmltag("traffic_stats", "");

  msg_tot = basic_stats_xml(&pkt_stat->stats);
  msg_in = basic_stats_xml(&pkt_stat->stats_in);
  msg_out = basic_stats_xml(&pkt_stat->stats_out);
  msg_proto = protocol_stack_xml(&pkt_stat->stats_protos, "protocols");
  msg = xmltag("traffic_stats",
               "\n<active_packets>%u</active_packets>\n"
               "<in>\n%s</in>\n"
               "<out>\n%s</out>\n"
               "<tot>\n%s</tot>\n"
               "%s",
               pkt_stat->pkt_list.length,
               msg_in, msg_out, msg_tot, msg_proto);
  g_free(msg_tot);
  g_free(msg_in);
  g_free(msg_out);
  g_free(msg_proto);
  return msg;
}
