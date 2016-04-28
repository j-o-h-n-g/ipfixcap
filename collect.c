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
#include <silk/skipfix.h>
#include <silk/utils.h>
#include <silk/rwrec.h>
#include <silk/sklog.h>
#include <silk/skstream.h>

#include <silk/skipfix.h>

#include <fixbuf/public.h>
/* Copied from skipfix.c without static prefix */
#include "skipfix.h"

#define BUFSIZE 4096
#define SKI_EXTRWREC_TID        0xAFEB
#define SKI_TCP_STML_TID        0xAFEC

/* Global variables */
static gint quit = 0;

typedef struct {
  gint port;
  gchar *directory;
  gint rotate;
  gint threads;
} option_t;

option_t options;
//memset(&options,0,sizeof(options_t));

/* Function declaration from skipfix.c */
int
skiRwNextRecord(fBuf_t * fbuf,
		const skpc_probe_t * probe,
		skIPFIXSourceRecord_t * forward_rec,
		skIPFIXSourceRecord_t * reverse_rec, GError ** err);

/* Dummy error handler */
static void
_dummy(const gchar * log_domain,
       GLogLevelFlags log_level, const gchar * message, gpointer user_data)
{
	/* Dummy does nothing */
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

static int
SessionInit(fbInfoModel_t * model, fbSession_t * session, GError ** err)
{
	fbTemplate_t *tmpl = NULL;

	/* Add the full record template */
	tmpl = fbTemplateAlloc(model);
	if (!fbTemplateAppendSpecArray(tmpl, ski_rwrec_spec, 0, err)) {
		goto ERROR;
	}
	if (!fbSessionAddTemplate(session, TRUE, SKI_RWREC_TID, tmpl, err)) {
		goto ERROR;
	}

	/* Add the extended record template */
	tmpl = fbTemplateAlloc(model);
	if (!fbTemplateAppendSpecArray(tmpl, ski_rwrec_spec, 0, err)) {
		goto ERROR;
	}
	if (!fbTemplateAppendSpecArray(tmpl, ski_extrwrec_spec, 0, err)) {
		goto ERROR;
	}
	if (!fbSessionAddTemplate(session, TRUE, SKI_EXTRWREC_TID, tmpl, err)) {
		goto ERROR;
	}

	/* Add the TCP record template */
	tmpl = fbTemplateAlloc(model);
	if (!fbTemplateAppendSpecArray(tmpl, ski_tcp_stml_spec, 0, err)) {
		goto ERROR;
	}
	if (!fbSessionAddTemplate(session, TRUE, SKI_TCP_STML_TID, tmpl, err)) {
		goto ERROR;
	}

	skiAddSessionCallback(session);

	return 1;
 ERROR:
	fbTemplateFreeUnused(tmpl);
	return 0;

}

int NextRecord(fBuf_t * fbuf, rwRec * rec, GError ** err)
{

	ski_extrwrec_t fixrec;
	fbTemplate_t *tmpl = NULL;
	size_t len;
	uint16_t tid;
	TYPEOF_BITMAP bmap;

	if (!fBufSetInternalTemplate(fbuf, SKI_EXTRWREC_TID, err)) {
		return -1;
	}

	/* Get the next record */
	len = sizeof(fixrec);
	if (!fBufNext(fbuf, (uint8_t *) & fixrec, &len, err)) {
		return -1;
	}

	tmpl = fBufGetCollectionTemplate(fbuf, &tid);
	bmap = GET_BITMAP_FROM_TEMPLATE(tmpl);
	if (TEMPLATE_GET_BIT(bmap, sourceIPv4Address)) {
		printf("v4\n");
		/* we're good */
	} else if (TEMPLATE_GET_BIT(bmap, sourceIPv6Address)) {
		printf("v6\n");
	} else {
		printf("not v4 or v6 - template not found\n");
		//skiFlowIgnored(&fixrec, "IPv6 record");
		return 0;
	}

}

void *process(void *args)
{
/* Processes IPFIX received via glib queue */

	thread_init_struct *thread_data = args;
	GAsyncQueue *queue = thread_data->queue;
	struct sockaddr_in *socket = (struct sockaddr_in *)&thread_data->socket;
	queue_data_struct *queue_data;

	/* Dummy probe to keep rwNextRecord happy */
	skpc_probe_t probe;
	memset(&probe, 0, sizeof(skpc_probe_t));

	/* Get a string of the socket source IP for probe naming */
	char origin[16] = "";
	inet_ntop(AF_INET, &socket->sin_addr, origin, 16);

	g_print("New source coming from %s\n", origin);
	GError *error = NULL;

	/* Setup fixbuf */
	fbInfoModel_t *model;	// = skiInfoModel();
	model = fbInfoModelAlloc();
	fbInfoModelAddElementArray(model, ski_info_elements);
	fbInfoModelAddElementArray(model, ski_std_info_elements);

	fbSession_t *session;
	session = fbSessionAlloc(model);
	int rv;
	rv = SessionInit(model, session, &error);
	if (rv != 1) {
		printf("Session Init rv=%d\n", rv);
		exit(1);
	}

	fBuf_t *fbuf;
	fbuf = fBufAllocForCollection(session, NULL);

	while (quit == 0) {

		/* Create timestamp */
		struct timeval tv;
		struct tm ut;
		char ts[16] = "";
		gettimeofday(&tv, NULL);
		gmtime_r(&tv.tv_sec, &ut);
		strftime(ts, sizeof(ts), "%Y%m%d%H%M%S", &ut);

		/* Create the final file and tmpfile */
		char path[128] = "";
		snprintf(path, sizeof(path), "%s/P%s_%s.XXXXXX", options.directory,
			 ts, origin);

		int fd = mkstemp(path);
		if (fd == -1) {
			printf("Error opening %s\n", path);
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
			fprintf(stderr, "Error is %s (errno=%d)\n",
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
		rv = skHeaderSetCompressionMethod(hdr, SK_COMPMETHOD_NONE);
		assert(rv == 0);
		char probename[32];
		snprintf(probename, 32, "P%s", origin);
		rv = skHeaderAddProbename(hdr, probename);
		assert(rv == 0);

		rv = skStreamWriteSilkHeader(stream);
		if (rv != 0) {
			skStreamPrintLastErr(stream, rv, &ERRMSG);
		}
		assert(rv == 0);

		GTimer *timer = g_timer_new();

		while ((g_timer_elapsed(timer, NULL) < options.rotate) && (quit == 0)) {

			/* Wait up to second for data */
			queue_data = g_async_queue_timeout_pop(queue, 1024);

			/* If nothing recived try again (checking timer) */
			if (queue_data == NULL)
				continue;

			if (queue_data->len == 0 || quit == 1)
				break;

			/* We quit the thread when we receive a 0 byte len */

			/* Also replicate this packet out again 
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
				rv = skiRwNextRecord(fbuf, &probe, &for_rec,
						     &rev_rec, &error);

				//rv = NextRecord(fbuf,&rec,&error);
				if (rv == -1) {
					break;
				} else if (rv == 0) {
					continue;
				} else if (rv == 1) {
					rv = skStreamWriteRecord(stream,
								 &for_rec);
				} else {
					g_error("stream rv=%d\n", rv);
				}
			}

			if (error->code != FB_ERROR_BUFSZ) {
				printf("Gerror: %d %s\n", error->code,
				       error->message);
				exit(1);
			}
			g_clear_error(&error);

			if (error != NULL) {
				g_error(error->message);
			}
			if (queue_data->buf != NULL)
				free(queue_data->buf);
			free(queue_data);
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

	fbInfoModelFree(model);
	model = NULL;

	//g_print("QueueThread terminating\n");
	return NULL;
}

void *do_work(void *arg)
{
	unsigned char buf[BUFSIZE];

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
		g_error("Failed to bind to port\n");
		return NULL;
	}

//	listen(listen_socket, 5);
//	fcntl(listen_socket, F_SETFL, O_NONBLOCK);


	// Initialise hash table for this thread
	GHashTable *hash = g_hash_table_new(g_int64_hash, g_int64_equal);
	gint64 *key;

	do {
		recvlen =
		    recvfrom(listen_socket, buf, BUFSIZE, 0,
			     (struct sockaddr *)&remote_addr, &addrlen);

		if (recvlen == -1) {
			if (quit == 1)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
		}

		assert(addrlen = sizeof(remote_addr));

		assert(remote_addr.sin_family == AF_INET);
		//Take first 8 bytes to use as hash for queue
		key = (gint64 *) & remote_addr;
		GAsyncQueue *queue;

		thread_kv = g_hash_table_lookup(hash, key);
		queue_data_struct *queue_data =
		    malloc(sizeof(queue_data_struct));
		queue_data->buf = malloc(recvlen);
		memcpy(queue_data->buf, buf, recvlen);
		queue_data->len = recvlen;

		if (thread_kv == NULL) {
			/* Queue not found to make a new one */
			thread_init_struct *args =
			    malloc(sizeof(thread_init_struct));
			queue = g_async_queue_new();
			args->queue = queue;
			memcpy(&args->socket, &remote_addr, sizeof(remote_addr));

			thread_kv = malloc(sizeof(thread_key_struct));

			thread_kv->thread = g_thread_new(NULL, &process, args);
			thread_kv->queue = queue;
			g_hash_table_insert(hash, key, thread_kv);
			g_async_queue_push(queue, queue_data);
		} else {
			/* We already have a queue so push this data down the queue we already have */
			//printf("Found\n");
			g_async_queue_push(thread_kv->queue, queue_data);
		}

	}
	while (quit == 0);

	GHashTableIter iter;
	gpointer k, v;

	/* Join each queue thread. Push 0 len down first to wake them up */
	g_hash_table_iter_init(&iter, hash);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		// Push nothing to the queue
		queue_data_struct *queue_data =
		    malloc(sizeof(queue_data_struct));
		queue_data->len = 0;
		queue_data->buf = NULL;
		g_async_queue_push((*(thread_key_struct *) v).queue,
				   queue_data);
		g_thread_join((*(thread_key_struct *) v).thread);
	}
	//   }

	close(listen_socket);

	return 0;
}

void term(int signum)
{
	g_print("Waiting for threads to complete!\n");
	quit = 1;
}

void process_options(int argc, char *argv[])
{

	GError *error = NULL;
	GOptionContext *context;

	static GOptionEntry entries[] = {
		{"directory", 'd', 0, G_OPTION_ARG_STRING, &options.directory,
		 "Output Directory", NULL},
		{"port", 'p', 0, G_OPTION_ARG_INT, &options.port,
		 "Port to receive IPFIX on", NULL},
		{"rotate", 'r', 0, G_OPTION_ARG_INT,&options.rotate,
		"Rotate file every N seconds", NULL},
		{"threads", 't', 0, G_OPTION_ARG_INT, &options.threads,
		"Number of threads for UDP listener", NULL},
		{NULL}
	};

	context = g_option_context_new("IPFIX Collector");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_print("Failed parsing options: %s\n", error->message);
		exit(1);
	}

	if ((options.directory == NULL ) || (options.port == 0 ) || (options.rotate == 0)) {
		g_print("%s\n",g_option_context_get_help(context, TRUE, NULL));
		exit(1);
	}

	if (options.threads == 0)
		options.threads=4;

}

int main(int argc, char *argv[])
{
	int i;

	SILK_FEATURES_DEFINE_STRUCT(features);

	/* This set global option variables */
	process_options(argc, argv);

	skAppRegister(argv[0]);
	skAppVerifyFeatures(&features, NULL);

	/* Catch CTRL-C and instruct threads to terminate cleanly */
	signal(SIGINT, term);

	g_log_set_handler(NULL, G_LOG_LEVEL_MASK, _dummy, NULL);

	const int MAX_THREADS = options.threads;

	GThread *tid[MAX_THREADS];
	for (i = 0; i < MAX_THREADS; i++) {
		tid[i] = g_thread_new(NULL, &do_work, NULL); //&options.port);
	}

	/* Wait for them to return */
	for (i = 0; i < MAX_THREADS; i++) {
		g_thread_join(tid[i]);
	}
	return 0;
}
