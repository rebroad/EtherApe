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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include "appdata.h"
#include "basic_stats.h"
#include "util.h"

static long packet_list_item_n = 0;

/***************************************************************************
 *
 * utility functions
 *
 **************************************************************************/

/* Returns a timeval structure with the time difference between to
 * other timevals. result = a - b */
struct timeval subtract_times(struct timeval a, struct timeval b)
{
  struct timeval result;

  /* Perform the carry for the later subtraction by updating b. */
  if (a.tv_usec < b.tv_usec) {
    int nsec = (b.tv_usec - a.tv_usec) / 1000000 + 1;
    b.tv_usec -= 1000000 * nsec;
    b.tv_sec += nsec;
  }
  if (a.tv_usec - b.tv_usec > 1000000) {
    int nsec = (a.tv_usec - b.tv_usec) / 1000000;
    b.tv_usec += 1000000 * nsec;
    b.tv_sec -= nsec;
  }

  /* result.tv_usec is positive. */
  result.tv_sec = a.tv_sec - b.tv_sec;
  result.tv_usec = a.tv_usec - b.tv_usec;
  return result;
}                               /* subtract_times */

/* returns the time difference a-b expressed in ms */
double subtract_times_ms(const struct timeval *a, const struct timeval *b)
{
  double result;

  result = (a->tv_sec - b->tv_sec) * 1000.0 + (a->tv_usec - b->tv_usec) / 1000.0;

#if CHECK_EXPIRATION
  {
    struct timeval t = subtract_times(*a, *b);
    double ck = (double)(t.tv_sec*1000.0 + t.tv_usec/1000.0);
    if (fabs(ck - result) > 0.000001)
      g_warning("Errore subtract_times_ms: ms: %.f, timeval: %.f, delta: %.10f",
                result, ck, fabs(ck-result));
  }
#endif

  return result;
}



/***************************************************************************
 *
 * packet_protos_t implementation
 *
 **************************************************************************/

static void packet_protos_delete(packet_protos_t *pt)
{
  guint i;
  for (i = 0; i <= STACK_SIZE; ++i)
    g_free(pt->protonames[i]);
}

/***************************************************************************
 *
 * packet_list_item_t implementation
 *
 **************************************************************************/
long packet_list_item_count(void)
{
  return packet_list_item_n;
}

packet_list_item_t *packet_list_item_create(packet_info_t *i, packet_direction d)
{
  packet_list_item_t *newit;

  g_assert(i);

  newit = g_malloc(sizeof(packet_list_item_t));
  g_assert(newit);

  /* increments refcount of packet */
  i->ref_count++;

  /* fills item, adding it to pkt list */
  newit->info = i;
  newit->direction = d;
  ++packet_list_item_n;
  return newit;
}

void packet_list_item_delete(packet_list_item_t *pli)
{
  if (pli) {
    if (pli->info) {
      /* packet exists, decrement ref count */
      pli->info->ref_count--;

      if (pli->info->ref_count < 1) {
        /* packet now unused, delete it */
        packet_protos_delete(&pli->info->prot_desc);
        g_free(pli->info);
        pli->info = NULL;

        /* global packet stats */
        appdata.total_mem_packets--;
      }
    }

    g_free(pli);
    --packet_list_item_n;
  }
}

/***************************************************************************
 *
 * basic_stats_t implementation
 *
 **************************************************************************/
/* resets counters */
void basic_stats_reset(basic_stats_t *tf_stat)
{
  g_assert(tf_stat);
  tf_stat->average = 0;
  tf_stat->aver_accu = 0;
  tf_stat->accumulated = 0;
  tf_stat->avg_size = 0;
  tf_stat->accu_packets = 0;
  tf_stat->last_time = appdata.now;
}

/* accumulate another basic_stats */
void basic_stats_sum(basic_stats_t *tf_stat, const basic_stats_t *tosum)
{
  g_assert(tf_stat);
  g_assert(tosum);
  tf_stat->accumulated += tosum->accumulated;
  tf_stat->aver_accu += tosum->aver_accu;
  tf_stat->accu_packets += tosum->accu_packets;
  if (subtract_times_ms(&tf_stat->last_time, &tosum->last_time) < 0)
    tf_stat->last_time = tosum->last_time;
  tf_stat->avg_size = tf_stat->accumulated / tf_stat->accu_packets;

  /* averages are calculated by basic_stats_avg */
}

void basic_stats_add(basic_stats_t *tf_stat, gdouble val)
{
  g_assert(tf_stat);
  tf_stat->accumulated += val;
  tf_stat->aver_accu += val;
  ++tf_stat->accu_packets;
  tf_stat->last_time = appdata.now;
  tf_stat->avg_size = tf_stat->accumulated / tf_stat->accu_packets;
  /* averages are calculated by basic_stats_avg */
}

void basic_stats_sub(basic_stats_t *tf_stat, gdouble val)
{
  g_assert(tf_stat);
  tf_stat->aver_accu -= val;
  if (!tf_stat->aver_accu)
    tf_stat->average = 0;
  tf_stat->avg_size = tf_stat->accumulated / tf_stat->accu_packets;
  /* averages are calculated by basic_stats_avg */
}

void basic_stats_avg(basic_stats_t *tf_stat, gdouble avg_msecs)
{
  g_assert(tf_stat);

  /* average in bps, and timer in ms, so we multiply by 8 and 1000 */
  if (avg_msecs != 0)
    tf_stat->average = 8000 * tf_stat->aver_accu / avg_msecs;
}

/* returns a newly allocated string with a dump of the stats */
gchar *basic_stats_dump(const basic_stats_t *tf_stat)
{
  gchar *msg;
  gchar *msg_time;
  if (!tf_stat)
    return g_strdup("basic_stats_t NULL");

  msg_time = timeval_to_str(tf_stat->last_time);
  msg = g_strdup_printf("avg: %f, avg_acc: %f, total: %f, avg_size: %f, "
                        "packets: %lu, last heard: %s",
                        tf_stat->average,
                        tf_stat->aver_accu,
                        tf_stat->accumulated,
                        tf_stat->avg_size,
                        tf_stat->accu_packets,
                        msg_time);

  g_free(msg_time);
  return msg;
}

/* returns a newly allocated string with an xml dump of the stats */
gchar *basic_stats_xml(const basic_stats_t *tf_stat)
{
  gchar *msg;
  double diffms;

  if (!tf_stat)
    return xmltag("stats", "");

  diffms = subtract_times_ms(&appdata.now, &tf_stat->last_time);
  // recalculates average size for better accuracy
  msg = xmltag("stats",
               "\n<avg>%.0f</avg>\n"
               "<total>%.0f</total>\n"
               "<avg_size>%.0f</avg_size>\n"
               "<packets>%lu</packets>\n"
               "<last_heard>%f</last_heard>\n",
               tf_stat->average,
               tf_stat->accumulated,
               tf_stat->accu_packets != 0 ? (double)tf_stat->accumulated / (double)tf_stat->accu_packets : (double)0.0,
               tf_stat->accu_packets,
               diffms / 1000.0);
  return msg;
}

