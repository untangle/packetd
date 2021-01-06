// Untangle Traffic Predictor Daemon
// Copyright (c) 2020 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include <semaphore.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <mysql/mysql.h>
/*---------------------------------------------------------------------------*/
#ifndef DATALOC
#define DATALOC extern
#endif
#ifndef VERSION
#define VERSION "DEVVER"
#endif
#ifndef BUILDID
#define BUILDID __DATE__ " " __TIME__
#endif
/*---------------------------------------------------------------------------*/
#define UNKNOWN_TRAFFIC	"{\"Application\":\"Unknown\",\"Confidence\":0}"
#define THREAD_LIMIT	32		// sets the maximum number of threads supported
#define SOCKET_LIMIT	1024	// sets maximum number of listen sockets supported

/*---------------------------------------------------------------------------*/
struct client_request
{
	MYSQL	*mydb;
	int		version;
	char	uid[64];
	char	address[64];
	int		port;
	int		protocol;
};
/*---------------------------------------------------------------------------*/
struct client_response
{
	char	appid[32];
	char	name[64];
	char	category[64];
	char	protochain[256];
	int		confidence;
	int		productivity;
	int		risk;
};
/*---------------------------------------------------------------------------*/
DATALOC struct timeval	g_runtime;
DATALOC pthread_mutex_t	g_loggerlock;
DATALOC pthread_t		g_threadhandle[THREAD_LIMIT];
DATALOC sem_t			g_threadflag;
DATALOC int				g_threadidx[THREAD_LIMIT];
DATALOC int				g_shutdown;
DATALOC int				g_netsock;
DATALOC unsigned int	g_netvalue[SOCKET_LIMIT];
DATALOC char			g_netaddress[SOCKET_LIMIT][32];
DATALOC int				g_netsocket[SOCKET_LIMIT];
DATALOC int				g_netcount;
DATALOC int				g_pollsock;

DATALOC char			cfg_SQLhostname[64];
DATALOC char			cfg_SQLusername[64];
DATALOC char			cfg_SQLpassword[64];
DATALOC char			cfg_SQLdatabase[64];
DATALOC int				cfg_SQLport;
DATALOC long			cfg_SQLflag;
DATALOC int				cfg_threadcount;
DATALOC int				cfg_serverport;
DATALOC int				cfg_console;
DATALOC int				cfg_debug;
/*---------------------------------------------------------------------------*/
#undef DATALOC
/*---------------------------------------------------------------------------*/
void sighandler(int sigval);
int socket_startup(void);
void socket_destroy(void);
void* socket_worker(void* argument);
void enumerate_interfaces(void);
void process_traffic(MYSQL *mydb,int netsock);
int process_query(struct client_request *request,char *target,int length);
uint64_t result_to_value(MYSQL *mydb);
char* result_to_string(MYSQL *mydb,char *target,int length);
int result_to_client(MYSQL *mydb,struct client_response *response);
int lookup_to_client(MYSQL *mydb,struct client_response *response);
void show_help(void);
/*---------------------------------------------------------------------------*/
void LogMessage(int level,const char *format,...);
void LogBinary(int level,const char *info,const void *buffer,int length);
void WriteMessage(int level,const char *message);
char *VALUEtoLEVEL(int value,char *dest);
/*---------------------------------------------------------------------------*/

