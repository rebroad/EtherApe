/* EtherApe
 * Copyright (C) 2000 Juan Toledo, Riccardo Ghetta
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

#include "appdata.h"
#include "stats/node.h"

void init_names(void);
void cleanup_names(void);

/* decode names from packet for both nodes */
void get_packet_names(protostack_t *src_node_pstk,
                      protostack_t *dst_node_pstk,
                      const guint8 *packet,
                      guint16 size,
                      const packet_protos_t *packet_prot_stack,
                      int link_type);

