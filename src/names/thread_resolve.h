/*
   Etherape
   Copyright (C) 2005 R.Ghetta

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* initialize dns interface - returns 0 on success */
int thread_open(void);

/* closes dns interface */
void thread_close(void);

/* resolves address and returns its fqdn */
const char *thread_lookup(address_t *address);
