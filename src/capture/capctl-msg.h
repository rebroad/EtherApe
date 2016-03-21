/*
 * Copyright (C) 2014, 2016 Zev Weiss <zev@bewilderbeest.net>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef CAPCTL_MSG_H
#define CAPCTL_MSG_H

#include <pcap.h>

typedef enum
{
  CRQ_PING, /* Only used during init to check liveness */
  CRQ_LISTDEVS,
  CRQ_STARTCAP,
  CRQ_SETFILTER,
  CRQ_GETSTATS,
  CRQ_STOPCAP,
  CRQ_EXIT,
} capctl_reqtype_t;

struct capctl_req_t
{
  capctl_reqtype_t type;
  union
  {
    struct { } ping;
    struct { } listdevs;

    struct
    {
      size_t devlen;
    } startcap;

    struct
    {
      size_t bpflen;
    } setfilter;

    struct { } stopcap;
    struct { } exit;
    struct { } getstats;
  };
};

typedef enum
{
  CRP_OK,
  CRP_ERR,
} capctl_status_t;

struct capctl_resp_t
{
  capctl_status_t status;
  union
  {
    struct
    {
      size_t msglen;
    } err;

    struct { } ping;

    struct
    {
      size_t len;
    } listdevs;

    struct
    {
      size_t devlen;
      int linktype;
    } startcap;

    struct { } setfilter;
    struct { } stopcap;
    struct { } exit;

    struct
    {
      struct pcap_stat stats;
    } getstats;
  };
};

#endif
