#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <glib.h>
#include <gio/gio.h>
#include <assert.h>
#include <error.h>
#include <fcntl.h>

#include <silk/silk.h>
#include <silk/libflowsource.h>
//#include <silk/skipfix.h>
#include <silk/utils.h>
#include <silk/rwrec.h>
#include <silk/sklog.h>
#include <silk/skstream.h>

#include <systemd/sd-journal.h>


#include <fixbuf/public.h>
//#include "libflowsource.h"
/* Structures copied from skipfix.c without static prefix */
//#include "skipfix.h"

#include "skipfix-legacy.h"

#define BUFSIZE 2048
//#define SKI_EXTRWREC_TID        0xAFEB
//#define SKI_TCP_STML_TID        0xAFEC

/* Global variables */
enum status_enum { STATUS_INIT, STATUS_GO, STATUS_QUIT };
volatile enum status_enum status = STATUS_INIT;

typedef struct {
  gint port;
  gchar *directory;
  gchar *sensor_conf;
  gint timeout;
  gint maxfilesize;
  gint threads;
  gchar *pidfile;
  gboolean nodaemon;
  gint compress;
} option_t;

static option_t options;

/* Function declaration from skipfix.c */
int
skiRwNextRecord(fBuf_t * fbuf,
		const skpc_probe_t * probe,
		skIPFIXSourceRecord_t * forward_rec,
		skIPFIXSourceRecord_t * reverse_rec, GError ** err);

/* Dummy error handler */

static const gchar *
log_level_to_string (GLogLevelFlags level)
{
  switch (level)
    {
      case G_LOG_LEVEL_ERROR: return "ERROR";
      case G_LOG_LEVEL_CRITICAL: return "CRITICAL";
      case G_LOG_LEVEL_WARNING: return "WARNING";
      case G_LOG_LEVEL_MESSAGE: return "MESSAGE";
      case G_LOG_LEVEL_INFO: return "INFO";
      case G_LOG_LEVEL_DEBUG: return "DEBUG";
      default: return "UNKNOWN";
    }
}

static void
log_handler(const gchar * log_domain,
       GLogLevelFlags log_level, const gchar * message, gpointer user_data)
{

const gchar *log_level_str;


   log_level_str = log_level_to_string (log_level & G_LOG_LEVEL_MASK);

  if (log_level < G_LOG_LEVEL_WARNING)
    {
	if (options.nodaemon)
      g_printerr ("%s: %s: %s\n", log_domain, log_level_str, message);
	else
	sd_journal_print(LOG_NOTICE,"%s: %s: %s\n", log_domain, log_level_str, message);
    }
  else if (log_level > G_LOG_LEVEL_WARNING)
    {
     if (options.nodaemon)
      g_print ("%s: %s: %s\n", log_domain, log_level_str, message);
     else
	sd_journal_print(LOG_NOTICE,"%s: %s: %s\n", log_domain, log_level_str, message);
    }



	return;
}

/* Data we pass when we initialise a thread */
typedef struct {
	GAsyncQueue *queue;
	struct sockaddr socket;
} thread_init_struct;

/* What each queue item contains */
typedef struct {
	void *buf;
	size_t len;
} queue_data_struct;


void *process(void *args)
{
/* Processes IPFIX received via glib queue */

	thread_init_struct *thread_data = args;
	GAsyncQueue *queue = thread_data->queue;
	struct sockaddr_in *socket = (struct sockaddr_in *)&thread_data->socket;
	queue_data_struct *queue_data;

	GTimer *timer = g_timer_new();
	
	/* Get a string of the socket source IP for probe naming */
	char origin[16] = "";
	inet_ntop(AF_INET, &socket->sin_addr, origin, 16);

	g_info("New source coming from %s:%d being processed by %p", origin,ntohs(socket->sin_port),g_thread_self());

	/* Find the probe name which correspond to this UDP source */
	const char *probename = NULL;
	skpc_probe_iter_t probe_iter;
	const skpc_probe_t *probe;
	sk_sockaddr_t *sockaddr;
	sockaddr=(sk_sockaddr_t*)socket;
	skpcProbeIteratorBind(&probe_iter);
	while (skpcProbeIteratorNext(&probe_iter, &probe)) {
		/* TODO: Also check port */
		if ((probe->protocol != SKPC_PROTO_UDP) || (probe->probe_type != PROBE_ENUM_IPFIX)) 
			continue;
		if ((probe->accept_from_addr == 0) || skSockaddrArrayContains(*probe->accept_from_addr,sockaddr,SK_SOCKADDRCOMP_NOPORT) ) {
			probename=probe->probe_name;
			/* Take first match, don't write to more than one probe source */
			break;
		}
		
	}

	if (probename == NULL) {
			/* No match found, just sink this data */
			g_timer_start(timer);
			while (status == STATUS_GO) {
				/* For the time being let this thread spin for ever */
	                        /* Wait up to second for data */
       		                queue_data = g_async_queue_timeout_pop(queue, 1024 * 1024);

                       		 /* If nothing recived try again (checking quit) */
                        	if (queue_data == NULL)
                                	continue;

				if (queue_data->len == 0 ) {
                                        g_slice_free(queue_data_struct,queue_data); 
                                        break;
	                        }

				if (g_timer_elapsed(timer,NULL) >= 10) {
					g_info("New data to unconfigured probe %s",origin);
					g_timer_start(timer); 
				}

				g_slice_free1(BUFSIZE,queue_data->buf);
				g_slice_free(queue_data_struct,queue_data);
			}
	} else {

	GError *error = NULL;

	/* Setup fixbuf */
	fbInfoModel_t *model = legacyskiInfoModel();
	//model = fbInfoModelAlloc();
	//fbInfoModelAddElementArray(model, ski_info_elements);
	//fbInfoModelAddElementArray(model, ski_std_info_elements);

	fbSession_t *session;
	session = fbSessionAlloc(model);
	int rv;
//	rv = SessionInit(model, session, &error);
	rv = legacyskiSessionInitReader(session,&error);

	if (rv != 1) {
		g_error("Session Init rv=%d %s %d", rv,strerror(errno), errno);
		exit(1);
	}

	legacyskiAddSessionCallback(session);

	fBuf_t *fbuf;
	fbuf = fBufAllocForCollection(session, NULL);

	while (status == STATUS_GO) {

		/* Create timestamp */
		struct timeval tv;
		struct tm ut;
		char ts[16] = "";
		gettimeofday(&tv, NULL);
		gmtime_r(&tv.tv_sec, &ut);
		strftime(ts, sizeof(ts), "%Y%m%d%H%M%S", &ut);

		/* Create the final file and tmpfile */
		char path[128] = "";
		snprintf(path, sizeof(path), "%s/%s_%s.XXXXXX", options.directory,
			 ts, probename);

		int fd = mkstemp(path);
		if (fd == -1) {
			g_error("Error opening %s", path);
			exit(1);
		}
		close(fd);
		char *filename;
		char dotpath[64] = "";
		filename = strrchr(path, '/');
		filename++;
		snprintf(dotpath, sizeof(dotpath), "%s/.%s", options.directory,
			 filename);
		fd = open(dotpath, O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (fd < 0) {
			g_error("Error is %s (errno=%d)",
				strerror(errno), errno);
		}
		assert(fd > 0);

		/* Create the stream and write the header */
		skstream_t *stream;

		rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK_FLOW);
		assert(rv==0);
		rv = skStreamBind(stream, dotpath);
		assert(rv==0);
		rv = skStreamFDOpen(stream, fd);
		assert(rv==0);

		sk_file_header_t *hdr;
		hdr = skStreamGetSilkHeader(stream);
		rv = skHeaderSetFileFormat(hdr, FT_RWIPV6ROUTING);
		assert(rv == 0);
		rv = skHeaderSetRecordVersion(hdr, SK_RECORD_VERSION_ANY);
		assert(rv == 0);
		rv = skHeaderSetByteOrder(hdr, SILK_ENDIAN_BIG);
		assert(rv == 0);
		rv = skHeaderSetCompressionMethod(hdr, options.compress);
		assert(rv == 0);
		rv = skHeaderAddProbename(hdr, probename);
		assert(rv == 0);

		rv = skStreamWriteSilkHeader(stream);
		if (rv != 0) {
			skStreamPrintLastErr(stream, rv, &ERRMSG);
		}
		assert(rv == 0);

		g_timer_start(timer);

		/* Now loop pulling data from queue and writing to silk file */
		while ((g_timer_elapsed(timer, NULL) < options.timeout) && (skStreamGetUpperBound(stream) < options.maxfilesize)) {

			/* Wait up to second for data */
			queue_data = g_async_queue_timeout_pop(queue, 1024 * 1024);

			/* If nothing recived try again (checking timer) */
			if (queue_data == NULL)
				continue;

			/* We quit the thread when we receive a 0 byte len */
			if (queue_data->len == 0 ) {
				g_slice_free(queue_data_struct,queue_data); // || status == STATUS_QUIT)
				break;
			}


			/* We could also replicate this packet out again 
			   if (sendto (s,datagram,iph->total_len,0,(struct sockaddr *) &sin, sizeof(sin)) < 0) {
			   perror("sendto failed\n");
			   } else {
			   printf("sendto passed\n");
			   }            */

			fBufSetBuffer(fbuf, queue_data->buf, queue_data->len);

			skIPFIXSourceRecord_t for_rec;
			skIPFIXSourceRecord_t rev_rec;
			int rv;
			while (1) {
				rv = skiRwNextRecord(fbuf, probe, &for_rec,
						     &rev_rec, &error);

				if (rv == -1) {
					break;
				} else if (rv == 0) {
					continue;
				} else if (rv == 1) {
					rv = skStreamWriteRecord(stream,
								 &for_rec);
				} else {
					g_error("stream rv=%d", rv);
				}
			}

			/* Should end with FB_ERROR_BUFSZ once buffer in empty */
			if (error->code != FB_ERROR_BUFSZ) {
				g_error("Gerror: %d %s", error->code,
				       error->message);
				exit(1);
			}
			g_clear_error(&error);

			if (error != NULL) {
				g_error(error->message);
			}

			if (queue_data->buf != NULL)
				g_slice_free1(BUFSIZE,queue_data->buf);
			g_slice_free(queue_data_struct,queue_data);
		}
		rv = skStreamFlush(stream);
		assert(rv == 0);
		rv = skStreamClose(stream);
		assert(rv == 0);


		if (skStreamGetRecordCount(stream) == 0) {
			rv = unlink(dotpath);
			assert(rv == 0);
			rv = unlink(path);
			assert(rv == 0);
		} else {
			rv = rename(dotpath, path);
			assert(rv == 0);
		}

		skStreamDestroy(&stream);

	}

	fBufFree(fbuf);
	
	//legacyskiInfoModelFree();
	

	}

	g_timer_destroy(timer);
	g_slice_free(thread_init_struct,args);


	return NULL;
}

void *do_work(void *arg)
{
	unsigned char *buf = NULL;

	typedef struct {
		GThread *thread;
		GAsyncQueue *queue;
	} thread_key_struct;

	thread_key_struct *thread_kv;

	int listen_socket = socket(AF_INET, SOCK_DGRAM, 0);
	int one = 1;
	setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &one,
		   sizeof(one));

	struct timeval timeout = { 2, 0 };	//set timeout for 2 seconds

	/* set receive UDP message timeout */
	setsockopt(listen_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
		   sizeof(struct timeval));

	/* Try to increase socket buffer size */
	int n = 10 * 1024 * 1024;  // 10Mb
	if (setsockopt(listen_socket, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) == -1)
	{
		g_error("Failed to set SO_RCVBUF to %d",n);
	}  else {
		g_info("Set SO_RCVBUF to %d",n);
	}
	/* Ignore failures and just go with the default */

	struct sockaddr_in serv_addr;
	struct sockaddr_in remote_addr;
	int recvlen;
	socklen_t addrlen = sizeof(remote_addr);
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(options.port);

	int ret = bind(listen_socket, (struct sockaddr *)&serv_addr,
		       sizeof(serv_addr));
	if (ret == -1) {
		g_error("Failed to bind to port");
		return NULL;
	}

	do {
		g_info("Waiting for all threads to start");
	} while (status == STATUS_INIT);



	// Initialise hash table for this thread
	GHashTable *hash = g_hash_table_new(g_int64_hash, g_int64_equal);
	gint64 *key;

	do {
		/* Freed by receiving thread */
		if (buf == NULL) {
			buf=g_slice_alloc(BUFSIZE);
		}
		assert(buf != NULL);

		recvlen =
		    recvfrom(listen_socket, buf, BUFSIZE, 0,
			     (struct sockaddr *)&remote_addr, &addrlen);

		if (recvlen == -1) {
			if (status == STATUS_QUIT) {
				g_slice_free1(BUFSIZE,buf);
				break;
			}
			if (errno == EAGAIN ) { // || errno == EWOULDBLOCK) {
				continue;
			}
		}

		assert(addrlen = sizeof(remote_addr));

		assert(remote_addr.sin_family == AF_INET);
		//Take first 8 bytes to use as hash for queue which should include the IPV4 src ip
		key = (gint64 *) & remote_addr;
		GAsyncQueue *queue;

		thread_kv = g_hash_table_lookup(hash, key);
		queue_data_struct *queue_data =
		    g_slice_new(queue_data_struct);
		queue_data->buf = buf;
		queue_data->len = recvlen;
		/* Memory freed by receiving thread so clear buf here so we allocate some more memory on next loop*/
		buf=NULL;

		if (thread_kv == NULL) {
			/* Queue not found to make a new one */
			thread_init_struct *args =
			    g_slice_new(thread_init_struct);
			queue = g_async_queue_new();
			args->queue = queue;
			memcpy(&args->socket, &remote_addr, sizeof(remote_addr));

			thread_kv = g_slice_new(thread_key_struct);

			/* Copy the key so it survives before inserting */
			gint64 *newkey=g_slice_new(gint64);
			memcpy(newkey,key,sizeof(gint64));

			thread_kv->thread = g_thread_new(NULL, &process, args);
			thread_kv->queue = queue;
			g_hash_table_insert(hash, newkey, thread_kv);
			g_async_queue_push(queue, queue_data);
		} else {
			/* We already have a queue so push this data down the queue we already have */
			g_async_queue_push(thread_kv->queue, queue_data);
		}

	}
	while (status == STATUS_GO);

	

	GHashTableIter iter;
	gpointer k, v;

	/* Join each queue thread. Push 0 len down first to wake them up */
	g_hash_table_iter_init(&iter, hash);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		// Push nothing to the queue
		queue_data_struct *queue_data =
		    g_slice_new(queue_data_struct);
		queue_data->len = 0;
		queue_data->buf = NULL;
		g_async_queue_push((*(thread_key_struct *) v).queue,
				   queue_data);
		// Wait for it to finish
		g_thread_join((*(thread_key_struct *) v).thread);
		g_async_queue_unref((*(thread_key_struct *) v).queue);
		g_slice_free(thread_key_struct,v);
		g_slice_free(gint64,k);
	}
	g_hash_table_destroy (hash);

	close(listen_socket);

	return 0;
}

void term(int signum)
{
	g_info("Waiting for threads to complete!");
	status = STATUS_QUIT;
}

void process_options(int argc, char *argv[])
{

	GError *error = NULL;
	GOptionContext *context;
	static gchar *compression = NULL;
	memset(&options,0,sizeof(option_t));

	static GOptionEntry entries[] = {
		{"destination-directory", 'd', 0, G_OPTION_ARG_STRING, &options.directory,
		 "Output Directory", NULL},
		{"port", 'p', 0, G_OPTION_ARG_INT, &options.port,
		 "Port to receive IPFIX on", NULL},
		{"timeout", 0, 0, G_OPTION_ARG_INT,&options.timeout,
		"Rotate file every N seconds", NULL},
		{"max-file-size",0,0,G_OPTION_ARG_INT,&options.maxfilesize,
		"Maximum Filesize", NULL},
		{"threads", 't', 0, G_OPTION_ARG_INT, &options.threads,
		"Number of threads for UDP listener", NULL},
		{"sensor-configuration",'s',0,G_OPTION_ARG_STRING, &options.sensor_conf,
	        "Sensor Configuration File", NULL},
   		{"pidfile",0,0, G_OPTION_ARG_STRING, &options.pidfile,
	        "Location of pidfile", NULL},	
		{"no-daemon",0,0,G_OPTION_ARG_NONE, &options.nodaemon,
		"Do not fork off as a daemon (for debugging)", NULL},
		{"compression-method",0,0,G_OPTION_ARG_STRING,&compression,
		"Compression Method [none,zlib,lzo1x,best]", NULL },
		{NULL}
	};

	context = g_option_context_new("IPFIX Collector");
	g_option_context_add_main_entries(context, entries, NULL);

	/* ignore remaining options */
	g_option_context_set_ignore_unknown_options(context,true);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_print("Failed parsing options: %s", error->message);
		exit(1);
	}

	if ((options.maxfilesize == 0 ) || (options.directory == NULL ) || (options.sensor_conf == NULL) || (options.port == 0 ) || (options.timeout == 0) || (options.pidfile == NULL)) {
		g_print("%s",g_option_context_get_help(context, TRUE, NULL));
		exit(1);
	}

	if (options.threads == 0)
		options.threads=4;

	if ((compression == NULL) || (!strcmp(compression,"best") ))
		options.compress=SK_COMPMETHOD_BEST;
	else if (!strcmp(compression,"none")) 
		options.compress=SK_COMPMETHOD_NONE;
	else if (!strcmp(compression,"lzo1x"))
		options.compress=SK_COMPMETHOD_LZO1X;
	else if (!strcmp(compression,"zlib"))
		options.compress=SK_COMPMETHOD_ZLIB;
	else {
		g_print("%s",g_option_context_get_help(context, TRUE, NULL));
                exit(1);
        }

	
	g_free(compression);
	g_option_context_free(context);


}

void create_pidfile() 
{
FILE *pidfile = g_fopen(options.pidfile,"w");

if (pidfile == NULL)  {
	g_critical("Failed to open pid file \n");
 } else {
	g_fprintf(pidfile,"%d\n",getpid());
	fclose(pidfile);
}

}

void remove_pidfile() 
{
/* Try to remove pid file. Intentionally ignore error */
unlink(options.pidfile);
}

void daemonize()
{

pid_t pid;
int rv;

pid=fork();

if (pid < 0) {
	exit(EXIT_FAILURE);
} 
if (pid > 0) {
	exit(EXIT_SUCCESS);
}
if (setsid() < 0)
        exit(EXIT_FAILURE);

pid=fork();

if (pid < 0) {
        exit(EXIT_FAILURE);
}

if (pid > 0) {
	exit(EXIT_SUCCESS);
}

/* chdir */
rv=chdir("/");
if (rv != 0) {
	g_error("%s",strerror(errno));
	exit(1);
}

/* close file descriptors 
if (!freopen( "/dev/null", "r", stdin)) 
	g_error("%s",strerror(errno));
if (!freopen( "/dev/null", "w", stdout))
	g_error("%s",strerror(errno));
if (!freopen( "/dev/null", "w", stderr))
	g_error("%s",strerror(errno));
*/

/* write pid file */
create_pidfile();

/* Set signal handler */
//signal(SIGINT, term);

/* start logging */

}



int main(int argc, char *argv[])
{
	int i;


	SILK_FEATURES_DEFINE_STRUCT(features);

	/* This set global option variables */
	process_options(argc, argv);

	if (!options.nodaemon) {
		daemonize();
        }

	skAppRegister(argv[0]);
	skAppVerifyFeatures(&features, NULL);
	skpcSetup();
	skpcParse(options.sensor_conf,NULL);

	/* Catch CTRL-C and instruct threads to terminate cleanly */
	signal(SIGINT, term);
	signal(SIGTERM, term);

	g_log_set_handler(NULL, G_LOG_LEVEL_MASK, log_handler, NULL);

	const int MAX_THREADS = options.threads;

	GThread *tid[MAX_THREADS];
	for (i = 0; i < MAX_THREADS; i++) {
		tid[i] = g_thread_new(NULL, &do_work, NULL); //&options.port);
	}
	/* Houston you are GO! */
	status=STATUS_GO;

	/* Wait for them to return */
	for (i = 0; i < MAX_THREADS; i++) {
		g_thread_join(tid[i]);
	}

	remove_pidfile();
	g_free(options.pidfile);
	g_free(options.directory);
	g_free(options.sensor_conf);
	legacyskiInfoModelFree();
	
	return 0;
}
