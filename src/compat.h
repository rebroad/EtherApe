/* compat.h
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

#ifndef __COMPAT_H__
#define __COMPAT_H__

#if !defined(HAVE_G_LIST_FREE_FULL)
void compat_g_list_free_full(GList *list, GDestroyNotify free_func);
#define g_list_free_full  compat_g_list_free_full
#endif

#if !defined(HAVE_G_PTR_ARRAY_INSERT)
void compat_g_ptr_array_insert(GPtrArray *farray, gint index_, gpointer data);
#define g_ptr_array_insert  compat_g_ptr_array_insert
#endif

#endif /* __COMPAT_H__ */
