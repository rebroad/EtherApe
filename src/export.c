/* export.c
 * Exporting routines
 * Copyright (C) 2011 Riccardo Ghetta
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <locale.h>

#include "stats/node.h"
#include "stats/links.h"
#include "stats/util.h"
#include "export.h"

static gchar *header_xml(unsigned long totpkts)
{
  gchar *dvc = NULL;
  gchar *xml;
  time_t timenow;
  const struct tm *tmnow;
  char timebuf[256];

  if (appdata.source.type == ST_FILE)
    dvc = xmltag_escaped("capture_file", appdata.source.file);
  else if (appdata.source.interface)
    dvc = xmltag_escaped("capture_device", appdata.source.interface);

  timenow = time(NULL);
  tmnow = localtime(&timenow);
  strftime(timebuf, sizeof(timebuf), "%F %T %z", tmnow);
  xml = xmltag("header",
               "\n%s<timestamp>%s</timestamp>"
               "\n<packets>%lu</packets>\n",
               dvc ? dvc : "",
               timebuf,
               totpkts);
  g_free(dvc);
  return xml;
}

gchar *generate_xml(unsigned long totpkts)
{
  gchar *xmlh;
  gchar *xmln;
  gchar *xmll;
  gchar *xmlp;
  gchar *xml;
  gchar *oldlocale;

  // we want to dump in a known locale, so force it as 'C'
  oldlocale = g_strdup(setlocale(LC_ALL, NULL));
  setlocale(LC_ALL, "C");

  xmlh = header_xml(totpkts);
  xmln = nodes_catalog_xml();
  xmll = links_catalog_xml();
  xmlp = protocol_summary_xml();
  xml = g_strdup_printf("<?xml version=\"1.0\"?>\n"
                        "<!-- traffic data in bytes. last_heard in seconds from dump time -->\n"
                        "<etherape>\n%s%s%s%s</etherape>",
                        xmlh,
                        xmln,
                        xmll,
                        xmlp);
  // reset user locale
  setlocale(LC_ALL, oldlocale);

  g_free(xmlp);
  g_free(xmll);
  g_free(xmln);
  g_free(xmlh);
  g_free(oldlocale);
  return xml;
}


void dump_xml(gchar *ofile,unsigned long totpkts)
{
  FILE *fout;
  gchar *xml;

  if (!ofile)
    return;

  xml = generate_xml(totpkts);
  g_assert(xml);

  fout = fopen(ofile, "wb");
  if (fout) {
    fprintf(fout, "%s", xml);
    fclose(fout);
  }

  g_free(xml);
}
