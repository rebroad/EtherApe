/* compat.c
 * Compatibility functions
 *
 * Copyright 2016 Riccardo Ghetta
 *
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
#include <glib.h>
#include "appdata.h"

/************************************************
 *
 * compatibility functions
 *
 *************************************************/

void compat_g_list_free_full(GList *list, GDestroyNotify free_func)
{
  g_assert(free_func);

  /* free_func has one parameter, GFunc two ... - works only on cdecl */
  g_list_foreach(list, (GFunc)free_func, NULL);
  g_list_free(list);
}

void compat_g_ptr_array_insert(GPtrArray *parray,
                               gint idx,
                               gpointer data)
{
  gint pos;

  g_assert(parray);
  g_assert(idx >= -1);
  g_assert(idx <= parray->len);

  if (idx < 0) {
    g_ptr_array_add(parray, data);
    return;
  }

  /* adds empty element at end, then moves previous elements */
  g_ptr_array_add(parray, NULL);
  for (pos = parray->len; pos > idx; --pos)
    g_ptr_array_index(parray, pos) = g_ptr_array_index(parray, pos-1);
  g_ptr_array_index(parray, idx) = data;
}
