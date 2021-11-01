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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <pcap.h>

#include "cap-util.h"
#include "capctl-msg.h"
#include "capture.h"

static int ctrlsock = -1;
static int pktpipe = -1;
static pcap_t *pcap = NULL;
static int pcap_fd = -1;

/* non-glib convenience wrappers */
static inline void *xmalloc(size_t sz)
{
  void *p = malloc(sz);
  if (!p) {
    perror("malloc failure");
    abort();
  }
  return p;
}

static inline char *xstrdup(const char *s)
{
  char *new = strdup(s);
  if (!new) {
    perror("strdup failure");
    abort();
  }
  return new;
}

static inline void xfree(void *p)
{
  free(p);
}

#define __xmessage(pfx, fmt, ...)  fprintf(stderr, pfx ": "fmt "\n", ## __VA_ARGS__)
#define xwarning(fmt, ...)         __xmessage("warning", fmt, ## __VA_ARGS__)
#define xerror(fmt, ...)           __xmessage("error", fmt, ## __VA_ARGS__)
#define xcritical(fmt, ...)        __xmessage("critical", fmt, ## __VA_ARGS__)

static inline void ctrl_send(const void *buf, size_t len)
{
  if (write_all(ctrlsock, buf, len)) {
    xcritical("write_all() failed on control socket");
    exit(1);
  }
}

static inline void ctrl_recv(void *buf, size_t len)
{
  if (read_all(ctrlsock, buf, len)) {
    xcritical("read_all() failed on control socket");
    exit(1);
  }
}

static inline void sendresp(const struct capctl_resp_t *resp)
{
  ctrl_send(resp, sizeof(*resp));
}

static inline void zeroresp(struct capctl_resp_t *resp)
{
  memset(resp, 0, sizeof(*resp));
}

static void senderrmsg(const char *msg)
{
  struct capctl_resp_t resp;
  zeroresp(&resp);
  resp.status = CRP_ERR;
  resp.err.msglen = strlen(msg);
  sendresp(&resp);
  ctrl_send(msg, resp.err.msglen);
}

static void sendstr(const char *str)
{
  ctrl_send(str, strlen(str));
}

static char *recvstr(size_t len)
{
  char *str = xmalloc(len + 1);
  ctrl_recv(str, len);
  str[len] = '\0';
  return str;
}

static void sendok(void)
{
  struct capctl_resp_t resp;
  zeroresp(&resp);
  resp.status = CRP_OK;
  sendresp(&resp);
}
static void handle_ping(const struct capctl_req_t *req)
{
  sendok();
}

static void handle_listdevs(const struct capctl_req_t *req)
{
  struct capctl_resp_t resp;
  pcap_if_t *alldevs;
  pcap_if_t *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  int status;

  zeroresp(&resp);

  status = pcap_findalldevs(&alldevs, errbuf);
  if (status != 0) {
    senderrmsg(errbuf);
    return;
  }

  resp.listdevs.len = 0;

  for (dev = alldevs; dev; dev = dev->next)
    resp.listdevs.len += strlen(dev->name) + 1;

  resp.listdevs.len += 1; /* for final list-terminating NUL byte */
  resp.status = CRP_OK;

  sendresp(&resp);

  for (dev = alldevs; dev; dev = dev->next)
    ctrl_send(dev->name, strlen(dev->name) + 1);

  /* List terminator */
  ctrl_send("", 1);

  pcap_freealldevs(alldevs);
}

/* TODO: screen refresh rate? */
#define PCAP_TIMEOUT  250

static void handle_startcap(const struct capctl_req_t *req)
{
  char *devname;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct capctl_resp_t resp;

  zeroresp(&resp);

  if (pcap) {
    senderrmsg("capture already running");
    return;
  }

  if (!req->startcap.devlen) {
    senderrmsg("zero device length");
    return;
  }
  else
    devname = recvstr(req->startcap.devlen);

  pcap = pcap_open_live(devname, MAXCAPSIZE, 1, PCAP_TIMEOUT, errbuf);
  if (!pcap) {
    xfree(devname);
    senderrmsg(errbuf);
    return;
  }

  pcap_fd = pcap_get_selectable_fd(pcap);
  if (pcap_fd < 0) {
    senderrmsg("failed to get selectable pcap fd");
    xfree(devname);
    pcap_close(pcap);
    pcap = NULL;
    return;
  }

  if (pcap_setnonblock(pcap, 1, errbuf) == -1)
    xwarning("Failed to set pcap nonblocking: %s", errbuf);

  resp.status = CRP_OK;
  resp.startcap.linktype = pcap_datalink(pcap);
  resp.startcap.devlen = strlen(devname);
  sendresp(&resp);
  sendstr(devname);
  xfree(devname);
}

static void handle_setfilter(const struct capctl_req_t *req)
{
  char *bpfstr;
  struct capctl_resp_t resp;
  struct bpf_program bpfprog;
  int status;

  zeroresp(&resp);

  bpfstr = recvstr(req->setfilter.bpflen);

  if (!pcap) {
    senderrmsg("no pcap device started");
    return;
  }

  /* TODO: netmask? */
  status = pcap_compile(pcap, &bpfprog, bpfstr, 1, PCAP_NETMASK_UNKNOWN);
  xfree(bpfstr);

  if (status) {
    senderrmsg(pcap_geterr(pcap));
    return;
  }

  status = pcap_setfilter(pcap, &bpfprog);
  pcap_freecode(&bpfprog);

  if (status) {
    senderrmsg(pcap_geterr(pcap));
    return;
  }

  resp.status = CRP_OK;
  sendresp(&resp);
}

static void handle_getstats(const struct capctl_req_t *req)
{
  struct capctl_resp_t resp;

  zeroresp(&resp);

  if (!pcap) {
    senderrmsg("no pcap device started");
    return;
  }

  if (pcap_stats(pcap, &resp.getstats.stats)) {
    senderrmsg(pcap_geterr(pcap));
    return;
  }

  resp.status = CRP_OK;
  sendresp(&resp);
}

static void handle_stopcap(const struct capctl_req_t *req)
{
  if (pcap) {
    pcap_close(pcap);
    pcap = NULL;
    pcap_fd = -1;
    sendok();
  }
  else
    senderrmsg("already stopped");
}

static void handle_exit(const struct capctl_req_t *req)
{
  if (pcap) {
    pcap_close(pcap);
    pcap = NULL;
    pcap_fd = -1;
  }
  sendok();
  close(ctrlsock);
  close(pktpipe);
  exit(0);
}

static void (*const handlers[])(const struct capctl_req_t *) = {
  [CRQ_PING] = handle_ping,
  [CRQ_LISTDEVS] = handle_listdevs,
  [CRQ_STARTCAP] = handle_startcap,
  [CRQ_SETFILTER] = handle_setfilter,
  [CRQ_GETSTATS] = handle_getstats,
  [CRQ_STOPCAP] = handle_stopcap,
  [CRQ_EXIT] = handle_exit,
};

static void handle_ctrlmsg(void)
{
  struct capctl_req_t req;

  ctrl_recv(&req, sizeof(req));
  if (req.type < sizeof(handlers)/sizeof(handlers[0]) && handlers[req.type])
    handlers[req.type](&req);
  else {
    xcritical("unknown request type %d", req.type);
    exit(1);
  }
}

/* Single-packet in-memory buffer in case pktpipe blocks */
static struct
{
  char buf[MAXCAPSIZE + sizeof(struct pcap_pkthdr)];
  size_t buffered, offset;
} pktbuf = {
  .buffered = 0,
  .offset = 0,
};

static void flush_pktbuf(void)
{
  ssize_t status;

  assert(pktbuf.offset < pktbuf.buffered);

  while (pktbuf.offset < pktbuf.buffered) {
    status = write(pktpipe, pktbuf.buf + pktbuf.offset,
                   pktbuf.buffered - pktbuf.offset);
    if (status < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      else {
        perror("pktpipe write(2) failed");
        abort();
      }
    }
    else {
      pktbuf.offset += status;
    }
  }
  pktbuf.buffered = pktbuf.offset = 0;
}

static void handle_packet(void)
{
  struct pcap_pkthdr *hdr;
  const unsigned char *data;
  int status;

  assert(pktbuf.buffered == 0);

  status = pcap_next_ex(pcap, &hdr, &data);
  if (status == 1) {
    pktbuf.buffered = sizeof(*hdr) + hdr->caplen;
    assert(pktbuf.buffered <= sizeof(pktbuf.buf));

    memcpy(pktbuf.buf, hdr, sizeof(*hdr));
    memcpy(pktbuf.buf + sizeof(*hdr), data, hdr->caplen);

    flush_pktbuf();
  }
  else if (status < 0)
    xerror("pcap_next_ex failed: %s", pcap_geterr(pcap));
}

void pktcap_run(int csockfd, int ppipefd)
{
  fd_set rfds, wfds;
  int maxfd, status;

  ctrlsock = csockfd;
  pktpipe = ppipefd;

  set_fd_nonblock(ctrlsock, 1);
  set_fd_nonblock(pktpipe, 1);

  for (;;) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    maxfd = -1;

    FD_SET(ctrlsock, &rfds);
    maxfd = maxfd > ctrlsock ? maxfd : ctrlsock;

    if (pcap_fd >= 0) {
      FD_SET(pcap_fd, &rfds);
      maxfd = maxfd > pcap_fd ? maxfd : pcap_fd;
    }

    if (pktbuf.buffered > 0) {
      FD_SET(pktpipe, &wfds);
      maxfd = maxfd > pktpipe ? maxfd : pktpipe;
    }

    status = select(maxfd+1, &rfds, &wfds, NULL, NULL);
    if (status < 0) {
      xcritical("capture-loop select() failed");
      exit(1);
    }

    if (FD_ISSET(pktpipe, &wfds))
      flush_pktbuf();

    if (FD_ISSET(ctrlsock, &rfds)) {
      set_fd_nonblock(ctrlsock, 0);
      handle_ctrlmsg();
      set_fd_nonblock(ctrlsock, 1);
    }

    if (pcap_fd >= 0 && FD_ISSET(pcap_fd, &rfds) && pktbuf.buffered == 0)
      handle_packet();
  }
}
