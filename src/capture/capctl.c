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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <glib.h>
#include <pcap.h>

#include "preferences.h"
#include "appdata.h"
#include "stats/decode_proto.h"
#include "stats/protocols.h"
#include "stats/node.h"
#include "stats/links.h"
#include "export.h"
#include "cap-util.h"
#include "capctl.h"
#include "capctl-msg.h"
#include "capture.h"

/* For live capture */
static int ctrlsock = -1;
static int pktpipe = -1;
static pid_t pktcap_pid = -1;

/* For offline (file-sourced) capture */
static struct
{
  pcap_t *pcap;
  gboolean new;
  gint64 wait_ms;
  struct pcap_pkthdr lastpkt_hdr;
  unsigned char lastpkt_data[MAXCAPSIZE];
} filecap_state;

static capstatus_t capture_status = STOP;
static gint capture_source = -1;

static inline void zeroreq(struct capctl_req_t *req)
{
  memset(req, 0, sizeof(*req));
}

static void ctrl_recv(void *buf, size_t len)
{
  if (read_all(ctrlsock, buf, len))
    g_error(_("Failed to receive message from packet-capture process"));
}

static void ctrl_send(const void *buf, size_t len)
{
  if (write_all(ctrlsock, buf, len))
    g_error(_("Failed to send message to packet-capture process"));
}

static void pkt_recv(void *buf, size_t len)
{
  if (read_all(pktpipe, buf, len))
    g_error(_("Failed to receive packet from packet-capture process"));
}

static inline void sendreq(const struct capctl_req_t *req)
{
  ctrl_send(req, sizeof(*req));
}

static inline void recvresp(struct capctl_resp_t *resp)
{
  ctrl_recv(resp, sizeof(*resp));
}

/* FIXME: duplicated from capture.c */
static gchar *recvstr(size_t len)
{
  gchar *str = g_malloc(len + 1);
  ctrl_recv(str, len);
  str[len] = '\0';
  return str;
}

static void setenv_warn(const char *var, const char *value)
{
  if (setenv(var, value, 1))
    g_warning(_("Failed to set %s environment variable to '%s': %s"), var, value,
              strerror(errno));
}

/* Switch to the given (presumably un-privileged) user. */
static void privdrop(const gchar *user)
{
  struct passwd *pw;

  pw = getpwnam(user);

  if (!pw)
    g_error(_("Unknown user '%s'"), user);

  if (initgroups(pw->pw_name, pw->pw_gid)
      || setgid(pw->pw_gid)
      || setuid(pw->pw_uid))
    g_error(_("Failed to switch to user '%s' (uid=%lu, gid=%lu): %s"), user,
            (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid, strerror(errno));

  setenv_warn("USER", pw->pw_name);
  setenv_warn("USERNAME", pw->pw_name);
  setenv_warn("HOME", pw->pw_dir);
  setenv_warn("SHELL", pw->pw_shell);
}

gchar *init_capture(const gchar *user)
{
  int status;
  int sockfds[2];
  int pipefds[2];
  pid_t pid;
  struct capctl_req_t req;
  struct capctl_resp_t resp;
  gchar *errmsg;

  zeroreq(&req);

  capture_status = STOP;

  /* Create the socket via which we'll control the privileged pktcap process */
  status = socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds);
  if (status < 0)
    return g_strdup(strerror(errno));

  status = pipe(pipefds);
  if (status < 0)
    {
      close(sockfds[0]);
      close(sockfds[1]);
      return g_strdup(strerror(errno));
    }

  pid = fork();
  if (pid < 0)
    return g_strdup(strerror(errno));

  if (!pid)
    {
      /* child */
      if (close(sockfds[0]))
        g_warning("control socket close() failed: %s", strerror(errno));
      if (close(pipefds[0]))
        g_warning("packet pipe close() failed: %s", strerror(errno));
      pktcap_run(sockfds[1], pipefds[1]);
    }

  if (user)
    privdrop(user);

  /* parent */
  if (close(sockfds[1]))
    g_warning("control socket close() failed: %s", strerror(errno));
  if (close(pipefds[1]))
    g_warning("packet pipe close() failed: %s", strerror(errno));

  ctrlsock = sockfds[0];
  pktpipe = pipefds[0];

  req.type = CRQ_PING;
  ctrl_send(&req, sizeof(req));
  ctrl_recv(&resp, sizeof(resp));

  if (resp.status == CRP_OK)
    {
      set_fd_nonblock(pktpipe, 1);
      pktcap_pid = pid;
      return NULL;
    }
  else
    {
      errmsg = g_malloc(resp.err.msglen + 1);
      ctrl_recv(errmsg, resp.err.msglen);
      errmsg[resp.err.msglen] = '\0';
      return errmsg;
    }
}

GList *get_capture_interfaces(GString *err)
{
  gchar *raw_msg;
  gchar *devname;
  struct capctl_resp_t resp;
  struct capctl_req_t req;
  GList *ifs = NULL;

  zeroreq(&req);

  req.type = CRQ_LISTDEVS;

  sendreq(&req);
  recvresp(&resp);

  if (resp.status == CRP_ERR)
    {
      raw_msg = recvstr(resp.err.msglen);
      g_string_assign(err, raw_msg);
      g_free(raw_msg);
      return NULL;
    }

  g_assert(resp.status == CRP_OK);

  raw_msg = g_malloc(resp.listdevs.len);
  ctrl_recv(raw_msg, resp.listdevs.len);

  for (devname = raw_msg; *devname; devname += strlen(devname) + 1)
      ifs = g_list_prepend(ifs, g_strdup(devname));

  g_free(raw_msg);
  g_string_assign(err, "");
  return ifs;
}

static void
interface_list_free_cb(gpointer data, gpointer user_data)
{
  g_free(data);
}

void free_capture_interfaces(GList *ifs)
{
  g_list_foreach(ifs, interface_list_free_cb, NULL);
  g_list_free(ifs);
}

static void pktpipe_read_cb(gpointer data, gint source, GdkInputCondition cond)
{
  struct pcap_pkthdr pkthdr;
  char pktdata[MAXCAPSIZE];

  set_fd_nonblock(pktpipe, 0);
  pkt_recv(&pkthdr, sizeof(pkthdr));
  g_assert(pkthdr.caplen <= MAXCAPSIZE);
  pkt_recv(pktdata, pkthdr.caplen);
  set_fd_nonblock(pktpipe, 1);

  appdata.now = pkthdr.ts;

  packet_acquired((guint8*)pktdata, pkthdr.caplen, pkthdr.len);
}

static gchar *start_live_capture(unsigned int *linktype, int *select_fd)
{
  struct capctl_req_t req;
  struct capctl_resp_t resp;
  gchar *new_devname;

  zeroreq(&req);

  g_assert(appdata.source.type == ST_LIVE);

  req.type = CRQ_STARTCAP;
  req.startcap.devlen = appdata.source.interface ? strlen(appdata.source.interface) : 0;

  sendreq(&req);
  if (appdata.source.interface)
    ctrl_send(appdata.source.interface, req.startcap.devlen);

  recvresp(&resp);
  if (resp.status == CRP_ERR)
    return recvstr(resp.err.msglen);

  new_devname = recvstr(resp.startcap.devlen);
  if (appdata.source.interface)
    {
      g_assert(!strcmp(appdata.source.interface, new_devname));
      g_free(new_devname);
    }
  else
    appdata.source.interface = new_devname;

  *linktype = resp.startcap.linktype;
  *select_fd = pktpipe;

  return NULL;
}

/* FIXME: verify how this works w/ negatives... */
static inline gint64 tv_to_ms(const struct timeval *tv)
{
  gint64 ms = tv->tv_sec * 1000;
  if (ms > 0)
    ms += tv->tv_usec / 1000;
  else if (ms == 0)
    ms = tv->tv_usec / 1000;
  else
    ms -= tv->tv_usec / 1000;
  return ms;
}

static gboolean filecap_get_packet(gpointer unused)
{
  int status;
  struct pcap_pkthdr *nextpkt_hdr;
  const unsigned char *nextpkt_data;
  struct timeval pktdelta;
  size_t copylen;

  if (capture_status != PLAY)
    return FALSE;

  if (!filecap_state.new)
    {
      appdata.now = filecap_state.lastpkt_hdr.ts;
      packet_acquired((guint8*)filecap_state.lastpkt_data,
                      filecap_state.lastpkt_hdr.caplen,
                      filecap_state.lastpkt_hdr.len);
    }

  status = pcap_next_ex(filecap_state.pcap, &nextpkt_hdr, &nextpkt_data);
  if (status == -2)
    {
      capture_status = CAP_EOF;
      /* xml dump if needed */
      if (appdata.export_file_final)
        dump_xml(appdata.export_file_final);
      return FALSE;
    }
  else if (status == -1)
    {
      g_error("Failed to read packet from pcap file: %s",
              pcap_geterr(filecap_state.pcap));
      return FALSE;
    }
  else
    g_assert(status == 1);

  if (filecap_state.new)
    filecap_state.wait_ms = 0;
  else
    {
      timersub(&nextpkt_hdr->ts, &filecap_state.lastpkt_hdr.ts, &pktdelta);
      filecap_state.wait_ms = tv_to_ms(&pktdelta);
    }

  if (filecap_state.wait_ms < 0)
    filecap_state.wait_ms = 0;

  if (filecap_state.wait_ms < appdata.min_delay)
    filecap_state.wait_ms = appdata.min_delay;

  if (filecap_state.wait_ms > appdata.max_delay)
    filecap_state.wait_ms = appdata.max_delay;

  filecap_state.lastpkt_hdr = *nextpkt_hdr;
  if (nextpkt_hdr->caplen > MAXCAPSIZE)
    {
      filecap_state.lastpkt_hdr.caplen = MAXCAPSIZE;
      copylen = MAXCAPSIZE;
    }
  else
    copylen = nextpkt_hdr->caplen;
  memcpy(filecap_state.lastpkt_data, nextpkt_data, copylen);

  filecap_state.new = FALSE;

  return FALSE;
}

static void filecap_timeout_destroy(gpointer unused)
{
  if (capture_status == STOP)
    {
      pcap_close(filecap_state.pcap);
      filecap_state.pcap = NULL;
    }
  else if (capture_status == PLAY)
    capture_source = g_timeout_add_full(G_PRIORITY_DEFAULT, filecap_state.wait_ms,
                                        filecap_get_packet, NULL, filecap_timeout_destroy);
}

static gchar *start_file_capture(unsigned int *linktype)
{
  char errbuf[PCAP_ERRBUF_SIZE];

  g_assert(appdata.source.type == ST_FILE);
  g_assert(appdata.source.file);
  g_assert(!filecap_state.pcap);

  filecap_state.pcap = pcap_open_offline(appdata.source.file, errbuf);
  filecap_state.new = 1;
  if (!filecap_state.pcap)
    return g_strdup(errbuf);

  *linktype = pcap_datalink(filecap_state.pcap);

  return NULL;
}

gchar *start_capture(void)
{
  gchar *err;
  unsigned int linktype;
  int select_fd = -1;

  if (capture_status == STOP)
    {
      protocol_summary_open();
      nodes_catalog_open();
      links_catalog_open();
    }

  if (appdata.source.type == ST_LIVE)
    err = start_live_capture(&linktype, &select_fd);
  else
    err = start_file_capture(&linktype);

  if (err)
    {
      links_catalog_close();
      nodes_catalog_close();
      protocol_summary_close();
      return err;
    }

  /* FIXME: stop capture on errors past here */

  if (!setup_link_type(linktype))
    return g_strdup_printf(_("%s uses unsupported link type %d, cannot proceed."
                             "  Please choose another source."),
                           appdata_source_name(&appdata), linktype);

  if (appdata.mode == APEMODE_DEFAULT)
    {
      appdata.mode = IP;
      g_free(pref.filter);
      pref.filter = get_default_filter(appdata.mode);
    }
  else if (appdata.mode == LINK6 && !has_linklevel())
    return g_strdup_printf(_("This device does not support link-layer mode.  "
                             "Please use IP or TCP modes."));

  if (pref.filter)
    set_filter(pref.filter);

  capture_status = PLAY;

  if (appdata.source.type == ST_LIVE)
    capture_source = gdk_input_add(select_fd, GDK_INPUT_READ, pktpipe_read_cb,
                                   NULL);
  else
    capture_source = g_timeout_add_full(G_PRIORITY_DEFAULT, 1,
                                        filecap_get_packet, NULL,
                                        filecap_timeout_destroy);

  return err;
}

gchar *pause_capture(void)
{
  g_assert(capture_status == PLAY);
  capture_status = PAUSE;
  return NULL;
}

gchar *unpause_capture(void)
{
  g_assert(capture_status == PAUSE);

  if (appdata.source.type == ST_FILE)
    capture_status = g_timeout_add_full(G_PRIORITY_DEFAULT, 1,
                                        filecap_get_packet, NULL,
                                        filecap_timeout_destroy);

  capture_status = PLAY;
  return NULL;
}

static gchar *stop_live_capture(void)
{
  struct capctl_req_t req;
  struct capctl_resp_t resp;

  g_assert(appdata.source.type == ST_LIVE);

  zeroreq(&req);

  gdk_input_remove(capture_source);

  req.type = CRQ_STOPCAP;
  sendreq(&req);

  recvresp(&resp);

  if (resp.status == CRP_ERR)
    return recvstr(resp.err.msglen);

  g_assert(resp.status == CRP_OK);

  return NULL;
}

gchar *stop_capture(void)
{
  gchar *err = NULL;
  capstatus_t orig_state = capture_status;

  g_assert(capture_status == PLAY || capture_status == PAUSE
           || capture_status == CAP_EOF);

  /*
   * HACK: setting capture_status = STOP here (before the actual stop
   * operation) so that callbacks for file capture happening via timers will
   * see it and tear down.  We save the original state and restore it on
   * failure (kind of gross).
   */
  capture_status = STOP;

  if (appdata.source.type == ST_LIVE)
    err = stop_live_capture();
  else
    {
      if (orig_state == PLAY)
        {
          /*
           * If we're playing, the timeout destroy function will take care of
           * cleaning up closing and NULLing filecap_state.pcap.
           */
          g_source_remove(capture_source);
        }
      else if (orig_state == PAUSE || orig_state == CAP_EOF)
        {
          /*
           * But if we're stopping from a pause the timeout's not armed and
           * we'll need to do it here.
           */
          pcap_close(filecap_state.pcap);
          filecap_state.pcap = NULL;
        }
    }

  if (!err)
    {
      links_catalog_close();
      nodes_catalog_close();
      protocol_summary_close();
      new_nodes_clear();
    }
  else
    capture_status = orig_state;

  return err;
}

static gchar *cleanup_live_capture(void)
{
  struct capctl_req_t req;
  struct capctl_resp_t resp;
  int pktcap_status;
  pid_t pid;
  pid_t oldpid;

  if (pktcap_pid == -1)
    return NULL;
    
  zeroreq(&req);

  req.type = CRQ_EXIT;
  sendreq(&req);
  recvresp(&resp);

  if (resp.status == CRP_ERR)
    return recvstr(resp.err.msglen);

  g_assert(resp.status == CRP_OK);
  close(ctrlsock);
  ctrlsock = -1;

  // always reset pid
  oldpid = pktcap_pid;
  pktcap_pid = -1;

  pid = waitpid(oldpid, &pktcap_status, 0);
  if (pid != oldpid)
    return g_strdup_printf("waitpid() returned %d on capture process", pid);
  else if (!WIFEXITED(pktcap_status) || WEXITSTATUS(pktcap_status))
    return g_strdup_printf("capture process exited abnormally");

  return NULL;
}

void cleanup_capture(void)
{
  gchar *err = NULL;

  if (capture_status != STOP)
    {
      err = stop_capture();
      if (err)
        {
          g_error("failed to stop capture: %s", err);
          g_free(err);
        }
    }

  if (appdata.source.type == ST_FILE)
    g_assert(!filecap_state.pcap);

  /*
   * This happens unconditionally because even if we've been replaying from a
   * capture file, the live-capture process is still sitting around in the
   * background and needs to be stopped.
   */
  err = cleanup_live_capture();

  if (err)
    {
      g_error("Capture cleanup error: %s", err);
      g_free(err);
    }
}

void force_next_packet(void)
{
  g_assert(capture_status == PLAY);
  filecap_state.wait_ms = 0;
  g_source_remove(capture_source);
}

static gchar *set_live_filter(const gchar *filter)
{
  struct capctl_req_t req;
  struct capctl_resp_t resp;

  g_assert(appdata.source.type == ST_LIVE);

  zeroreq(&req);

  req.type = CRQ_SETFILTER;
  req.setfilter.bpflen = strlen(filter);

  sendreq(&req);
  ctrl_send(filter, req.setfilter.bpflen);

  recvresp(&resp);
  if (resp.status == CRP_ERR)
    return recvstr(resp.err.msglen);

  g_assert(resp.status == CRP_OK);
  return NULL;
}

static gchar *set_offline_filter(const gchar *filter)
{
  struct bpf_program bpfprog;

  g_assert(appdata.source.type == ST_FILE);

  if (!filecap_state.pcap)
    return g_strdup_printf("no capture file selected");

  /* TODO: netmask? */
  if (pcap_compile(filecap_state.pcap, &bpfprog, filter, 1, PCAP_NETMASK_UNKNOWN)
      || pcap_setfilter(filecap_state.pcap, &bpfprog))
    return g_strdup(pcap_geterr(filecap_state.pcap));

  return NULL;
}

gint set_filter(const gchar *filter)
{
  gchar *err;

  if (appdata.source.type == ST_LIVE)
    err = set_live_filter(filter);
  else
    err = set_offline_filter(filter);

  if (err)
    {
      g_error("failed to set filter: %s", err);
      g_free(err);
      return 1;
    }
  else
    return 0;
}

gchar *get_default_filter(apemode_t mode)
{
  switch (mode)
    {
    case IP:
      return g_strdup ("ip or ip6");

    case TCP:
      return g_strdup ("tcp");

    default:
      g_error("Invalid apemode %d", mode);
      /* Fallthrough */
    case LINK6:
      return g_strdup ("");
    }
}

static gchar *get_live_stats(struct pcap_stat *ps)
{
  struct capctl_req_t req;
  struct capctl_resp_t resp;

  zeroreq(&req);

  req.type = CRQ_GETSTATS;
  sendreq(&req);

  recvresp(&resp);

  if (resp.status == CRP_ERR)
    return recvstr(resp.err.msglen);

  g_assert(resp.status == CRP_OK);
  *ps = resp.getstats.stats;
  return NULL;
}

static gchar *get_filecap_stats(struct pcap_stat *ps)
{
  g_assert(appdata.source.type == ST_FILE);

  if (!filecap_state.pcap)
    return g_strdup("no capture file selected");

  if (pcap_stats(filecap_state.pcap, ps))
    return g_strdup(pcap_geterr(filecap_state.pcap));

  return NULL;
}

gchar *get_capture_stats(struct pcap_stat *ps)
{
  return (appdata.source.type == ST_FILE ? get_filecap_stats : get_live_stats)(ps);
}

capstatus_t get_capture_status(void)
{
  return capture_status;
}
