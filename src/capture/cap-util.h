/*
 * Capture utility definitions
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

#ifndef CAPUTIL_H
#define CAPUTIL_H

/*
 * read(2)/write(2) wrappers that either read 'count' bytes and return zero or
 * fail to do so and return non-zero.
 */
int write_all(int fd, const void *buf, size_t count);
int read_all(int fd, void *buf, size_t count);

/* Small wrapper to set (or unset) O_NONBLOCK on a file descriptor */
void set_fd_nonblock(int fd, int on);

#endif /* CAPUTIL_H */
