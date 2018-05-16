/**
 * classify.c
 *
 * Passes traffic to Sandvine library for classification
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

#include "classify.h"
/*--------------------------------------------------------------------------*/
static navl_handle_t l_navl_handle = (navl_handle_t)0;

// vars for library configuration
static int cfg_navl_debug = 0;
static int cfg_navl_defrag = 1;
static int cfg_http_limit = 0;
static int cfg_skype_confidence_thresh = 75;
static int cfg_skype_packet_thresh = 4;
static int cfg_skype_probe_thresh = 2;
static int cfg_skype_random_thresh = 85;
static int cfg_skype_require_history = 0;
static int cfg_skype_seq_cache_time = 30000;

// vars for the attribute names we track
static const char *l_name_facebook_app = "facebook.app";
static const char *l_name_tls_hostname = "tls.hostname";

// vars to hold the detail attributes we track
static int l_attr_facebook_app = INVALID_VALUE;
static int l_attr_tls_hostname = INVALID_VALUE;
/*--------------------------------------------------------------------------*/
int navl_callback(navl_handle_t handle,navl_result_t result,navl_state_t state,navl_conn_t conn,void *arg,int error)
{
	navl_iterator_t		it;
	unsigned int		ctid;
	char				protochain[256];
	char				appname[16];
	char				work[16];
	int					confidence;
	int					appid;
	int					value;

	// get the application id and confidence
	confidence = 0;
	appid = navl_app_get(handle,result,&confidence);

	appname[0] = 0;
	navl_proto_get_name(handle,appid,appname,sizeof(appname));

	protochain[0] = 0;

	// build the protochain
	for (it = navl_proto_first(handle,result);navl_proto_valid(handle,it);navl_proto_next(handle,it)) {
		// get the protocol index
		value = navl_proto_get_index(handle,it);
		work[0] = 0;
		navl_proto_get_name(handle,value,work,sizeof(work));

		// append the protocol name to the chain
		strncat(protochain,"/",sizeof(protochain)-1);
		strncat(protochain,work,sizeof(protochain)-1);
	}

	ctid = *(unsigned int *)arg;
	plugin_navl_callback(appname,protochain,ctid);
	return(0);
}
/*--------------------------------------------------------------------------*/
void attr_callback(navl_handle_t handle,navl_conn_t conn,int attr_type,int attr_length,const void *attr_value,int attr_flag,void *arg)
{
	unsigned int	ctid;
	char			detail[256];

	// we can't initialize our l_attr_xxx values during startup because the values
	// returned by vineyard are different for each thread so to work around this
	// we set them as invalid during startup and init the first time we are called
	if (l_attr_facebook_app == INVALID_VALUE) l_attr_facebook_app = navl_attr_key_get(handle,l_name_facebook_app);
	if (l_attr_tls_hostname == INVALID_VALUE) l_attr_tls_hostname = navl_attr_key_get(handle,l_name_tls_hostname);

	detail[0] = 0;

	// check for the facebook application name
	if (attr_type == l_attr_facebook_app) {
		memcpy(detail,attr_value,attr_length);
		detail[attr_length] = 0;
	}

	// check for the tls host name
	else if (attr_type == l_attr_tls_hostname) {
		memcpy(detail,attr_value,attr_length);
		detail[attr_length] = 0;
	}

	ctid = *(unsigned int *)arg;
	plugin_attr_callback(detail,ctid);
}
/*--------------------------------------------------------------------------*/
int vendor_classify(const unsigned char *data,int length, unsigned int ctid)
{
	navl_classify(l_navl_handle,NAVL_ENCAP_IP,data,length,NULL,0,navl_callback,&ctid);
}
/*--------------------------------------------------------------------------*/
int vendor_log_message(const char *level, const char *func, const char *format, ... )
{
	va_list		va;
	char		buf[4096];
	int			res = 0;

	va_start(va, format);
	res = snprintf(buf, 4096, "%s: %s: ", level, func);
	res += vsnprintf(buf + res, 4096 - res, format, va);
	navl_diag_printf(buf);
	va_end(va);
	return(res);
}
/*--------------------------------------------------------------------------*/
void vendor_externals(void)
{
	/* memory allocation */
	navl_malloc_local = malloc;
	navl_free_local = free;
	navl_malloc_shared = malloc;
	navl_free_shared = free;

	/* ctype */
	navl_islower = islower;
	navl_isupper = isupper;
	navl_tolower = tolower;
	navl_toupper = toupper;
	navl_isalnum = isalnum;
	navl_isspace = isspace;
	navl_isdigit = isdigit;

	/* string functions */
	navl_atoi = atoi;
	navl_memcpy = memcpy;
	navl_memcmp = memcmp;
	navl_memset = memset;
	navl_strcasecmp = strcasecmp;
	navl_strchr = (const char* (*)(const char*, int))strchr;
	navl_strrchr = (const char* (*)(const char*, int))strrchr;
	navl_strcmp = strcmp;
	navl_strncmp = strncmp;
	navl_strcpy = strcpy;
	navl_strncpy = strncpy;
	navl_strerror = strerror;
	navl_strftime = (size_t (*)(char*, size_t, const char*, const struct navl_tm*))strftime;
	navl_strlen = strlen;
	navl_strpbrk = (const char* (*)(const char*, const char*))strpbrk;
	navl_strstr = (const char* (*)(const char*, const char*))strstr;
	navl_strtol = strtol;

	/* input/output */
	navl_printf = printf;
	navl_sprintf = sprintf;
	navl_snprintf = snprintf;
	navl_sscanf = sscanf;
	navl_putchar = putchar;
	navl_puts = puts;
	navl_diag_printf = printf;

	/* time */
	navl_gettimeofday = (int (*)(struct navl_timeval*, void*))gettimeofday;
	navl_mktime = (navl_time_t (*)(struct navl_tm*))mktime;

	/* math */
	navl_log = log;
	navl_fabs = fabs;

	/* system */
	navl_abort = abort;
	navl_get_thread_id = (unsigned long (*)(void))pthread_self;
	navl_log_message = vendor_log_message;
}
/*--------------------------------------------------------------------------*/
int vendor_config(const char *key,int value)
{
	char		work[32];
	int			ret;

	sprintf(work,"%d",value);
	ret = navl_config_set(l_navl_handle,key,work);
	if (ret != 0) printf("NAVL: Error calling navl_config_set(%s)\n",key);
	return(ret);
}
/*--------------------------------------------------------------------------*/
int vendor_startup(void)
{
	const char	*check;
	char		work[32];
	int			problem = 0;
	int			junk,ret;
	int			l,x,y;

	// bind the vineyard external references
	vendor_externals();

	// spin up the vineyard engine
	l_navl_handle = navl_open(NULL);

	if (l_navl_handle == -1) {
		ret = navl_error_get(0);
		printf("NAVL: Error %d returned from navl_open()\n",ret);
		return(1);
	}

	// disable session timeout for TCP and UDP since we do the session management
	if (vendor_config("tcp.timeout",0) != 0) return(2);
	if (vendor_config("udp.timeout",0) != 0) return(3);

	// set the vineyard system loglevel parameter
	if (vendor_config("system.loglevel",cfg_navl_debug) != 0) return(4);

	// set the number of of http request+response pairs to analyze before giving up
	if (vendor_config("http.maxpersist",cfg_http_limit) != 0) return(5);

	// enable IP fragment processing
	if (vendor_config("ip.defrag",cfg_navl_defrag) != 0) return(6);

	// set all the low level skype parameters
	if (vendor_config("skype.confidence_thresh",cfg_skype_confidence_thresh) != 0) return(7);
	if (vendor_config("skype.packet_thresh",cfg_skype_packet_thresh) != 0) return(8);
	if (vendor_config("skype.probe_thresh",cfg_skype_probe_thresh) != 0) return(9);
	if (vendor_config("skype.random_thresh",cfg_skype_random_thresh) != 0) return(10);
	if (vendor_config("skype.require_history",cfg_skype_require_history) != 0) return(11);
	if (vendor_config("skype.seq_cache_time",cfg_skype_seq_cache_time) != 0) return(12);

	// initialize the vineyard handle for the active thread
	ret = navl_init(l_navl_handle);

	if (ret != 0) {
		printf("NAVL: Error %d returned from navl_init()\n",ret);
		return(13);
	}

	if ((navl_attr_callback_set(l_navl_handle,l_name_facebook_app,attr_callback) != 0))	problem|=0x01;
	if ((navl_attr_callback_set(l_navl_handle,l_name_tls_hostname,attr_callback) != 0))	problem|=0x02;

	if (problem != 0) {
		printf("NAVL: Error 0x%02X enabling metadata callbacks\n",problem);
		return(14);
	}

	// get the total number of protocols from the vineyard library
	ret = navl_proto_max_index(l_navl_handle);

	if (ret == -1) {
		printf("NAVL: Error calling navl_proto_max_index()\n");
		return(15);
	}

	return(0);
}
/*--------------------------------------------------------------------------*/
void vendor_shutdown(void)
{
	// finalize the vineyard library
	navl_fini(l_navl_handle);

	// shut down the vineyard engine
	navl_close(l_navl_handle);
}
/*--------------------------------------------------------------------------*/
