/*
 * Copyright (C) 2000 Juan Toledo, Riccardo Ghetta
 * Copyright (C) 2014, 2016 Zev Weiss
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
#ifndef ETHERAPE_CAPCTL_H
#define ETHERAPE_CAPCTL_H

#include <pcap.h>

#include "common.h"

/* Possible states of capture status */
typedef enum
{
  STOP = 0,
  PLAY = 1,
  PAUSE = 2,
  CAP_EOF = 3 /* end-of-file */
} capstatus_t;

capstatus_t get_capture_status(void);

gchar *init_capture(const gchar *user);

/*
 * Get a list containing the names of available capture interfaces.  Returns
 * NULL on error, with an error message in err_str.  The returned list must be
 * freed with free_capture_interfaces().
 */
GList *get_capture_interfaces(GString *err);
void free_capture_interfaces(GList *ifs);

gchar *start_capture(void);
gchar *pause_capture(void);
gchar *unpause_capture(void);
gchar *stop_capture(void);
void cleanup_capture(void);
void force_next_packet(void);
gint set_filter(const gchar * filter);
gchar *get_default_filter(apemode_t mode);
gchar *get_capture_stats(struct pcap_stat *ps);

#endif /* ETHERAPE_CAPCTL_H */
