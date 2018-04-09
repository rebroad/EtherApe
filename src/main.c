/* EtherApe
 * Copyright (C) 2001 Juan Toledo, Riccardo Ghetta
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
#include <config.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <netinet/in.h>
#include <signal.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <popt.h>
#include <gtk/gtk.h>
#include <libgnomecanvas/libgnomecanvas.h>
#include "appdata.h"
#include "names/ip-cache.h"
#include "main.h"
#include "diagram.h"
#include "preferences.h"
#include "info_windows.h"
#include "menus.h"
#include "capture/capctl.h"
#include "datastructs.h"
#include "names/dns.h"
#include "names/eth_resolv.h"
#include "names/names.h"
#include "stats/util.h"
#include "compat.h"

/***************************************************************************
 *
 * local variables
 *
 **************************************************************************/
static gboolean quiet = FALSE;
static void (*old_sighup_handler) (int);

/***************************************************************************
 *
 * internal functions
 *
 **************************************************************************/
static void free_static_data(void);
static void set_debug_level (void);
static void log_handler (gchar * log_domain, GLogLevelFlags mask, 
                         const gchar * message, gpointer user_data);
static GPtrArray *parse_position_file(const gchar *path);

/* signal handling */
static void install_handlers(void);
static void signal_export(int signum);

/***************************************************************************
 *
 * implementation
 *
 **************************************************************************/
int main (int argc, char *argv[])
{
  GtkWidget *widget;
  gchar *mode_string = NULL;
  gchar *cl_filter = NULL;
  gchar *cl_interface = NULL;
  gchar *cl_input_file = NULL;
  gchar *export_file_final = NULL;
  gchar *export_file_signal = NULL;
  gboolean cl_numeric = FALSE;
  glong midelay = 0;
  glong madelay = G_MAXLONG;
  gchar *errmsg;
  gchar *cl_glade_file = NULL;
  gchar *position_file_path = NULL;
  gchar *cl_privdrop_user = NULL;
  poptContext poptcon;

  struct poptOption optionsTable[] = {
    {"diagram-only", 'd', POPT_ARG_NONE, &(pref.diagram_only), 0,
     N_("don't display any node text identification"), NULL},
    {"replay-file", 'r', POPT_ARG_STRING, &cl_input_file, 0,
     N_("replay packets from file"), N_("<file to replay>")},
    {"filter", 'f', POPT_ARG_STRING, &cl_filter, 0,
     N_("set capture filter"), N_("<capture filter>")},
    {"interface", 'i', POPT_ARG_STRING, &cl_interface, 0,
     N_("set interface to listen to"), N_("<interface name>")},
    {"final-export", 0, POPT_ARG_STRING, &export_file_final, 0,
     N_("export to named file at end of replay"), N_("<file to export to>")},
    {"signal-export", 0, POPT_ARG_STRING, &export_file_signal, 0,
     N_("export to named file on receiving USR1"), N_("<file to export to>")},
    {"position", 'P', POPT_ARG_STRING, &position_file_path, 0,
     N_("Manually position nodes based on File"), N_("<list of nodes and their columns>")},
    {"stationary", 's', POPT_ARG_NONE, &(appdata.stationary_layout), 0,
     N_("don't move nodes around (deprecated)"), NULL},
    {"node-limit", 'l', POPT_ARG_INT, &(appdata.node_limit), 0,
     N_("limits nodes displayed"), N_("<number of nodes>")},
    {"mode", 'm', POPT_ARG_STRING, &mode_string, 0,
     N_("mode of operation"), N_("<link|ip|tcp>")},
    {"numeric", 'n', POPT_ARG_NONE, &cl_numeric, 0,
     N_("don't convert addresses to names"), NULL},
    {"quiet", 'q', POPT_ARG_NONE, &quiet, 0,
     N_("Disable informational messages"), NULL},
    {"min-delay", 0, POPT_ARG_LONG, &midelay,  0,
     N_("minimum packet delay in ms for reading capture files [cli only]"),
     N_("<delay>")},
    {"max-delay", 0, POPT_ARG_LONG, &madelay,  0,
     N_("maximum packet delay in ms for reading capture files [cli only]"),
     N_("<delay>")},
    {"glade-file", 0, POPT_ARG_STRING, &(cl_glade_file), 0,
     N_("uses the named libglade file for widgets"), N_("<glade file>")},
    {"relinquish-privileges", 'Z', POPT_ARG_STRING, &cl_privdrop_user, 0,
     N_("run as the given user"), N_("<username>")},

    POPT_AUTOHELP {NULL, 0, 0, NULL, 0, NULL, NULL}
  };

#ifdef ENABLE_NLS
  bindtextdomain(PACKAGE, PACKAGE_LOCALE_DIR);
  bind_textdomain_codeset(PACKAGE, "UTF-8"); /* force UTF-8 conversion */
  textdomain(PACKAGE);
#endif

  appdata_init(&appdata);

  /* Command line */
  poptcon = poptGetContext("Etherape", argc, (const char **)argv, optionsTable, 0);
  while (poptGetNextOpt(poptcon) > 0)
    ;
  poptFreeContext(poptcon);

  /*
   * Start the background capture process early so it doesn't end up with so
   * much gnome/glib/gtk crud attached to it.
   *
   * IMPORTANT: this must come before calling into glib, since it will cache
   * things and then not invalidate those caches when we setuid to the '-Z'
   * user id.  For example, load_config() calls config_file_name(), which in
   * turn calls g_get_user_config_dir(), which caches getenv(HOME), leading to
   * problems opening the user's config file later on (it will still be trying
   * to open a config file in root's $HOME instead of the unprivileged user's,
   * even after setuid()).
   */
  errmsg = init_capture(cl_privdrop_user);
  if (errmsg)
    {
      fatal_error_dialog(errmsg);
      return 1;
    }

  /* Load saved preferences */
  load_config(&pref);
  protohash_read_prefvect(pref.colors);
  centered_node_speclist = parse_nodeset_spec_list(pref.centered_nodes);

  pref.name_res = !cl_numeric;

  /* We set the window icon to use */
  if (!getenv ("GNOME_DESKTOP_ICON"))
    putenv ("GNOME_DESKTOP_ICON=" PIXMAPS_DIR "/etherape.png");

  gtk_init (&argc, &argv);

  set_debug_level();

  if (cl_interface)
    {
      appdata.source.type = ST_LIVE;
      appdata.source.interface = g_strdup(cl_interface);
    }

  if (export_file_final)
    {
      if (appdata.export_file_final)
	g_free (appdata.export_file_final);
      appdata.export_file_final = g_strdup (export_file_final);
    }
  if (export_file_signal)
    {
      if (appdata.export_file_signal)
	g_free (appdata.export_file_signal);
      appdata.export_file_signal = g_strdup (export_file_signal);
    }

  if (cl_input_file)
    {
      appdata_clear_source(&appdata);
      appdata.source.type = ST_FILE;
      appdata.source.file = g_strdup(cl_input_file);
    }

  /* Find mode of operation */
  if (mode_string)
    {
      if (strstr (mode_string, "link"))
	appdata.mode = LINK6;
      else if (strstr (mode_string, "ip"))
	appdata.mode = IP;
      else if (strstr (mode_string, "tcp"))
	appdata.mode = TCP;
      else
	g_warning (_
		   ("Unrecognized mode. Do etherape --help for a list of modes"));
      g_free(pref.filter);
      pref.filter = get_default_filter(appdata.mode);
    }

  if (cl_filter)
    {
      if (pref.filter)
	g_free (pref.filter);
      pref.filter = g_strdup (cl_filter);
    }

  if (midelay >= 0 && midelay <= G_MAXLONG)
    {
       appdata.min_delay = midelay;
       if (appdata.min_delay != 0)
         g_message("Minimum delay set to %lu ms", appdata.min_delay);
    }
  else
      g_message("Invalid minimum delay %ld, ignored", midelay);
  
  if (madelay >= 0 && madelay <= G_MAXLONG)
    {
      if (madelay < appdata.min_delay)
        {
          g_message("Maximum delay must be less of minimum delay");
          appdata.max_delay = appdata.min_delay;
        }
      else
        appdata.max_delay = madelay;
      if (appdata.max_delay != G_MAXLONG)
        g_message("Maximum delay set to %lu ms", appdata.max_delay);
    }
  else
      g_message("Invalid maximum delay %ld, ignored", madelay);

  if (position_file_path)
    appdata.column_patterns = parse_position_file(position_file_path);

  /* GtkBuilder */
  if (!appdata_init_builder(cl_glade_file))
    return 1;

  /* prepare decoders */
  services_init();

  /* Sets controls to the values of variables and connects signals */
  init_diagram(appdata.xml);

  if (!pref.show_statusbar)
    {
      widget = GTK_WIDGET(appdata.statusbar);
      gtk_widget_hide(widget);

      widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "status_bar_check"));
      gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), FALSE);
    }

  if (!pref.show_toolbar)
    {
      widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "handlebox_toolbar"));
      gtk_widget_hide(widget);

      widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "toolbar_check"));
      gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), FALSE);
    }

  if (!pref.show_legend)
    {
      widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "handlebox_legend"));
      gtk_widget_hide(widget);

      widget = GTK_WIDGET(gtk_builder_get_object(appdata.xml, "legend_check"));
      gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), FALSE);
    }

  gtk_widget_show (appdata.app1);

  install_handlers();

  /* With this we force an update of the diagram every x ms 
   * Data in the diagram is updated, and then the canvas redraws itself when
   * the gtk loop is idle. If the CPU can't handle the set refresh_period,
   * then it will just do a best effort */

  widget = canvas_widget();
  destroying_idle(widget);

  /* This other timeout makes sure that the info windows are updated */
  g_timeout_add(500, update_info_windows, NULL);

  if (pref.name_res && dns_open())
    g_warning(_("DNS resolver initialization failed"));

  init_names();
  init_eth_resolv();

  init_menus ();

  gui_start_capture ();

  /* MAIN LOOP */
  gtk_main ();

  free_static_data();
  return 0;
}

/*
 * Parse the given line of a node-position file into a speclist and a column
 * number, returning TRUE on success and FALSE on failure.
 *
 * Note: this modifies the string in place -- a bit ugly, but it's only used
 * in one place, and it'ss easier than allocating a local copy.
 */
static gboolean parse_position_line(gchar *line, GList **speclist, long *colnum)
{
  gchar *p;

  g_assert(line);
  line = g_strstrip(line);

  /* Empty line or comment */
  if (!line[0] || line[0] == '#')
    return FALSE;

  /*
   * Scan back from end to find beginning of column number at end of line.
   * The "- 1" starting point is safe because at this point we know that
   * strlen(line) > 0.
   */
  for (p = line + strlen(line) - 1; p > line; p--)
    {
      /* If we hit the character preceding the column number... */
      if (*p == ',' || isspace(*p))
        {
          /* ...advance back to the start of it and break. */
          p += 1;
          break;
        }
    }

  if (p == line || strict_strtol(p, 0, colnum))
    {
      fprintf(stderr, _("Invalid position-file line: %s"), line);
      return FALSE;
    }
  else if (*colnum <= 0 || *colnum > 1000)
    {
      fprintf(stderr, _("Column number %ld out of range"), *colnum);
      return FALSE;
    }

  /* 'p' > 'line' here; split the string just before the column number */
  p[-1] = '\0';

  *speclist = parse_nodeset_spec_list(line);

  return TRUE;
}

static GPtrArray *parse_position_file(const gchar *path)
{
  gchar *contents;
  gchar **lines;
  gsize len;
  GError *err;
  int i;
  long colnum;
  GList *speclist;
  GPtrArray *colpos = NULL;

  if (!g_file_get_contents(path, &contents, &len, &err))
    {
      fprintf(stderr, _("Failed to read position file %s: %s"), path, err->message);
      g_error_free(err);
      return NULL;
    }

  colpos = g_ptr_array_sized_new(10);

  lines = g_strsplit(contents, "\n", 0);
  g_free(contents);

  for (i = 0; lines[i]; i++)
    {
      if (parse_position_line(lines[i], &speclist, &colnum))
        {
          /* "user" column numbers are one-based; convert to zero-based here. */
          colnum -= 1;

          if (colnum > colpos->len)
            g_ptr_array_set_size(colpos, colnum);
          g_ptr_array_insert(colpos, colnum, speclist);
        }
    }

  g_strfreev(lines);
  return colpos;
}

/* releases all static and cached data. Called just before exiting. Obviously 
 * it's not stricly needed, since the memory will be returned to the OS anyway,
 * but makes finding memory leaks much easier. */
static void free_static_data(void)
{
  protohash_clear();
  ipcache_clear();
  services_clear();
  cleanup_eth_resolv();
  cleanup_names();
  appdata_free(&appdata);
}

static void
set_debug_level (void)
{
  const gchar *env_debug;
  env_debug = g_getenv("APE_DEBUG");

  appdata.debug_mask = (G_LOG_LEVEL_MASK & ~(G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO));

  if (env_debug)
    {
      if (!g_ascii_strcasecmp(env_debug, "INFO"))
        appdata.debug_mask = (G_LOG_LEVEL_MASK & ~G_LOG_LEVEL_DEBUG);
      else if (!g_ascii_strcasecmp(env_debug, "DEBUG"))
        appdata.debug_mask = G_LOG_LEVEL_MASK;
    }
  else
    appdata.debug_mask = (G_LOG_LEVEL_MASK & ~G_LOG_LEVEL_DEBUG);

  // ugly workaround for changed g_log_default_handler behaviour
  // unfortunately it can be controlled only by environment vars ...
  // Silly change!
  g_setenv("G_MESSAGES_DEBUG", "all", TRUE);
        
  if (quiet)
    appdata.debug_mask = 0;

  g_log_set_handler(NULL, G_LOG_LEVEL_MASK, (GLogFunc) log_handler, NULL);
  g_my_debug("debug_mask %d", appdata.debug_mask);
}

static void
log_handler (gchar * log_domain,
	     GLogLevelFlags mask, const gchar * message, gpointer user_data)
{
  if (mask & appdata.debug_mask)
    g_log_default_handler("EtherApe", mask, message, user_data);
}

/***************************************************************************
 *
 * signal handling
 *
 **************************************************************************/

/* installs signal handlers */
static void install_handlers(void)
{
  /* 
   * Signal handling
   * Catch SIGINT and SIGTERM and, if we get either of them, clean up
   * and exit.
   * XXX - deal with signal semantics on various platforms.  Or just
   * use "sigaction()" and be done with it?
   */
  if (signal(SIGTERM, cleanup) == SIG_IGN)
     signal(SIGTERM, SIG_IGN);
  if (signal(SIGINT, cleanup) == SIG_IGN)
     signal(SIGINT, SIG_IGN);
#if !defined(WIN32)
  if ((old_sighup_handler = signal (SIGHUP, cleanup)) != SIG_DFL)	/* Play nice with nohup */
    signal (SIGHUP, old_sighup_handler);
#endif
  if (signal(SIGUSR1, signal_export) == SIG_IGN)
     signal(SIGUSR1, SIG_IGN);
}

/*
 * Quit the program.
 * Makes sure that the capture device is closed, or else we might
 * be leaving it in promiscuous mode
 */
void cleanup(int signum)
{
  cleanup_capture();
  free_static_data();
  exit(0);
}

/* activates a flag requesting an xml dump */
static void signal_export(int signum)
{
  appdata.request_dump = TRUE;
}
