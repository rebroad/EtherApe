/*
 * Miscellaneous utility routines for packet-capture code
 *
 * Copyright (c) 2016 Zev Weiss
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "cap-util.h"

int write_all(int fd, const void *buf, size_t count)
{
  ssize_t written, total = 0;

  while (total < count) {
    written = write(fd, (const char *)buf + total, count - total);
    if (written < 0) {
      fprintf(stderr, "write(2) failed in write_all(): %s\n", strerror(errno));
      return -1;
    }
    total += written;
  }

  return 0;
}

int read_all(int fd, void *buf, size_t count)
{
  ssize_t nread, total = 0;

  while (total < count) {
    nread = read(fd, (char *)buf + total, count - total);
    if (nread < 0) {
      fprintf(stderr, "read(2) failed in read_all(): %s\n", strerror(errno));
      return -1;
    }
    else if (!nread) {
      fprintf(stderr, "unexpected EOF in read_all()\n");
      return -1;
    }
    total += nread;
  }

  return 0;
}

void set_fd_nonblock(int fd, int on)
{
  int status, flags;

  flags = fcntl(fd, F_GETFL);
  if (flags != -1)
    status = fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));

  if (flags == -1 || status == -1) {
    fprintf(stderr, "fcntl(2) failed in set_fd_nonblock(): %s\n", strerror(errno));
    abort();
  }
}
