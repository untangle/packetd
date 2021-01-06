// Untangle Traffic Predictor Daemon
// Copyright (c) 2020 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#define DATALOC
#include "predictor.h"
/*---------------------------------------------------------------------------*/
int main(int argc,const char *argv[])
{
struct timeval	tv;
struct rlimit	core;
fd_set			tester;
int				ret;
int				x;

gettimeofday(&g_runtime,NULL);

signal(SIGINT,sighandler);

// set the core dump file size limit
core.rlim_cur = 0x40000000;
core.rlim_max = 0x40000000;
setrlimit(RLIMIT_CORE,&core);

strcpy(cfg_SQLhostname,"localhost");
strcpy(cfg_SQLusername,"predictor");
strcpy(cfg_SQLpassword,"password");
strcpy(cfg_SQLdatabase,"untangle");
cfg_SQLport = 3306;
cfg_SQLflag = 0;

cfg_threadcount = get_nprocs();
cfg_serverport = 21818;
cfg_console = 1;
cfg_debug = 1;

	for(x = 1;x < argc;x++)
	{
	if (strncasecmp(argv[x],"-SQLhost=",9) == 0) strcpy(cfg_SQLhostname,&argv[x][9]);
	if (strncasecmp(argv[x],"-SQLuser=",9) == 0) strcpy(cfg_SQLusername,&argv[x][9]);
	if (strncasecmp(argv[x],"-SQLpass=",9) == 0) strcpy(cfg_SQLpassword,&argv[x][9]);
	if (strncasecmp(argv[x],"-SQLdb=",7) == 0) strcpy(cfg_SQLdatabase,&argv[x][7]);
	if (strncasecmp(argv[x],"-SQLport=",9) == 0) cfg_SQLport = atoi(&argv[x][9]);
	if (strncasecmp(argv[x],"-SQLflag=",9) == 0) cfg_SQLflag = atoi(&argv[x][9]);
	if (strncasecmp(argv[x],"-T=",3) == 0) cfg_threadcount = atoi(&argv[x][3]);
	if (strncasecmp(argv[x],"-P=",3) == 0) cfg_serverport = atoi(&argv[x][3]);
	if (strncasecmp(argv[x],"-D",2) == 0) cfg_debug++;
	if (strncasecmp(argv[x],"-L",2) == 0) cfg_console++;
	if (strncasecmp(argv[x],"-H",2) == 0) show_help();
	}

ret = pthread_mutex_init(&g_loggerlock,NULL);
	if (ret != 0)
	{
	printf("Error %d initializing the logger mutex\n",errno);
	return(1);
	}

// initialize the mysql library
mysql_library_init(0,NULL,NULL);

LogMessage(LOG_INFO,"Untangle Traffic Predictor Daemon Version %s\n",VERSION);
LogMessage(LOG_INFO,"Build Date %s\n",BUILDID);

	if (cfg_console == 0)
	{
	ret = fork();
		if (ret > 0)
		{
		LogMessage(LOG_INFO,"Daemon %d started successfully\n",ret);
		return(0);
		}
		if (ret < 0)
		{
		LogMessage(LOG_ERR,"Error %d on fork daemon process\n",errno);
		return(2);
		}

	// since we are forking we need to disconnect from the console
	freopen("/dev/null","r",stdin);
	freopen("/dev/null","w",stdout);
	freopen("/dev/null","w",stderr);
	}

enumerate_interfaces();
socket_startup();

	for(x = 0;x < cfg_threadcount;x++)
	{
	if (g_shutdown != 0) break;
	sem_init(&g_threadflag,0,0);
	g_threadidx[x] = x;
	pthread_create(&g_threadhandle[x],NULL,socket_worker,&g_threadidx[x]);
	sem_wait(&g_threadflag);
	sem_destroy(&g_threadflag);
	}

if (cfg_console != 0) LogMessage(LOG_NOTICE,"=== Running on console - Use ENTER or CTRL+C to terminate ===\n");

	while (g_shutdown == 0)
	{
		// if running on the console check for keyboard input
		if (cfg_console != 0)
		{
		FD_ZERO(&tester);
		FD_SET(fileno(stdin),&tester);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		ret = select(fileno(stdin)+1,&tester,NULL,NULL,&tv);
		if (ret == 0) continue;
		if(FD_ISSET(fileno(stdin),&tester) == 0) continue;
		LogMessage(LOG_NOTICE,"=== Console input detected - Setting shutdown flag ===\n");
		g_shutdown++;
		}
	}

LogMessage(LOG_INFO,"Waiting for worker threads to finish\n");

	for(x = 0;x < cfg_threadcount;x++)
	{
	pthread_join(g_threadhandle[x],NULL);
	}

socket_destroy();
pthread_mutex_destroy(&g_loggerlock);
mysql_library_end();
pthread_exit(0);
return(0);
}
/*---------------------------------------------------------------------------*/
void sighandler(int sigval)
{
	switch(sigval)
	{
	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		signal(sigval,sighandler);
		g_shutdown = 2;
		break;
	}
}
/*---------------------------------------------------------------------------*/
void show_help(void)
{
printf("\n** Untangle Traffic Predictor Daemon Version %s **\n",VERSION);
printf("\n---------- Database Configuration Options ----------\n");
printf("-SQLhost=host.domain.com\n");
printf("-SQLuser=username\n");
printf("-SQLpass=password\n");
printf("-SQLdb=database\n");
printf("-SQLport=3108\n");
printf("-SQLflag=0\n");
printf("\n---------- Daemon Configuration Options ----------\n");
printf("-T=xxx (set number of worker threads\n");
printf("-P=xxx (set the network service port\n");
printf("\n");
printf("---------- Command Line Flags ----------\n");
printf("-D  Enable debug logging\n");
printf("-L  Run on console without fork\n");
printf("-H  Print command line options\n");
printf("\n");
exit(0);
}
/*---------------------------------------------------------------------------*/
void enumerate_interfaces(void)
{
struct sockaddr_in	*ptr;
struct ifconf		info;
struct ifreq		*ifr;
char				*databuff;
int					doff,len;
int					sock;

// allocate buffer to hold the interface information
databuff = (char *)calloc(1024,256);
if (databuff == NULL) return;

// setup the interface request buffer
memset(&info,0,sizeof(info));
info.ifc_ifcu.ifcu_buf = databuff;
info.ifc_len = (256 * 1024);

// grab info about all the network interfaces
sock = socket(PF_INET,SOCK_STREAM,0);
ioctl(sock,SIOCGIFCONF,&info);
close(sock);

doff = 0;

	// walk through each entry in the buffer
	while (doff < info.ifc_len)
	{
	ifr = (struct ifreq *)&databuff[doff];

#ifdef HAVE_SOCKADDR_SA_LEN

	len = sizeof(struct sockaddr);
	if (ifr->ifr_addr.sa_len > len) len = ifr->ifr_addr.sa_len;

#else

	len = sizeof(ifr->ifr_ifru);

#endif

	// adjust the working offset
	doff+=sizeof(ifr->ifr_name);
	doff+=len;

	// ignore interfaces we don't care about or that are down
	if (ifr->ifr_ifru.ifru_addr.sa_family != AF_INET) continue;
	ptr = (struct sockaddr_in *)&ifr->ifr_addr;
	if (ptr->sin_addr.s_addr == 0) continue;

	// save the address in our list
	g_netvalue[g_netcount] = ptr->sin_addr.s_addr;

	// save the interface address dotted quad string
	inet_ntop(AF_INET,&ptr->sin_addr,g_netaddress[g_netcount],sizeof(g_netaddress[g_netcount]));
	g_netcount++;
	}

free(databuff);
}
/*---------------------------------------------------------------------------*/
void database_error(MYSQL *context,const char *function,const char *file,int line)
{
char	message[4096];
char	*spot;

spot = message;
spot+=sprintf(spot,"CRITICAL MYSQL ERROR IN %s\n",function);
spot+=sprintf(spot,"  ** FILE:%s  LINE:%d  CODE:%d\n",file,line,mysql_errno(context));
spot+=sprintf(spot,"  ** MESSAGE:%s\n",mysql_error(context));
LogMessage(LOG_ALERT,message);

// set the global shutdown flag
g_shutdown++;
}
/*---------------------------------------------------------------------------*/
int socket_startup(void)
{
struct sockaddr_in		addr;
int						val,ret;
int						total;
int						x;

total = 0;

	for(x = 0;x < g_netcount;x++)
	{
	// open a socket for the interface
	LogMessage(LOG_INFO,"Server listening on %s:%d\n",g_netaddress[x],cfg_serverport);

	g_netsocket[total] = socket(PF_INET,SOCK_DGRAM,0);
		if (g_netsocket[total] == -1)
		{
		LogMessage(LOG_ERR,"Error %d returned from socket(client)\n",errno);
		return(0);
		}

	// allow binding even with old sockets in TIME_WAIT status
	val = 1;
	ret = setsockopt(g_netsocket[total],SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));
		if (ret == -1)
		{
		LogMessage(LOG_ERR,"Error %d returned from setsockopt(SO_REUSEADDR)\n",errno);
		return(0);
		}

	// set socket to nonblocking mode
	ret = fcntl(g_netsocket[total],F_SETFL,O_NONBLOCK);
		if (ret == -1)
		{
		LogMessage(LOG_ERR,"Error %d returned from fcntl(O_NONBLOCK)\n",errno);
		return(0);
		}

	// bind the socket to our server interface
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg_serverport);
	addr.sin_addr.s_addr = inet_addr(g_netaddress[total]);
	ret = bind(g_netsocket[total],(struct sockaddr *)&addr,sizeof(addr));
		if (ret == -1)
		{
		LogMessage(LOG_ERR,"Error %d returned from bind(client)\n",errno);
		return(0);
		}

	// increment number of active interfaces
	total++;
	}

return(total);
}
/*---------------------------------------------------------------------------*/
void socket_destroy(void)
{
int		x;

	// shutdown and close all our sockets
	for(x = 0;x < g_netcount;x++)
	{
	LogMessage(LOG_INFO,"Disconnecting server from %s:%d\n",g_netaddress[x],cfg_serverport);
	if (g_netsocket[x] < 1) continue;
	shutdown(g_netsocket[x],SHUT_RDWR);
	close(g_netsocket[x]);
	}
}
/*---------------------------------------------------------------------------*/
void* socket_worker(void *argument)
{
struct timeval		tv;
fd_set				tester;
MYSQL				mydb;
int					mynum = *(int *)argument;
int					maxval;
int					ret;
int					x;

LogMessage(LOG_INFO,"Thread %d is starting\n",mynum);

// initialize a database context
mysql_thread_init();
memset(&mydb,0,sizeof(mydb));
mysql_init(&mydb);

// tell the library to look for options in our section of the my.cnf file
mysql_options(&mydb,MYSQL_READ_DEFAULT_GROUP,"predictor");

// create the database connection
mysql_real_connect(&mydb,cfg_SQLhostname,cfg_SQLusername,cfg_SQLpassword,cfg_SQLdatabase,cfg_SQLport,NULL,cfg_SQLflag);
ret = mysql_errno(&mydb);
	if (ret != 0)
	{
	database_error(&mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	mysql_close(&mydb);
	mysql_thread_end();
	g_shutdown++;
	sem_post(&g_threadflag);
	return(NULL);
	}

sem_post(&g_threadflag);

	while (g_shutdown == 0)
	{
	// wait for one of the sockets to receive something
	FD_ZERO(&tester);
	maxval = 0;

		for(x = 0;x < g_netcount;x++)
		{
		FD_SET(g_netsocket[x],&tester);
		if (g_netsocket[x] > maxval) maxval = g_netsocket[x];
		}

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(maxval+1,&tester,NULL,NULL,&tv);
	if (ret == 0) continue;

		for(x = 0;x < g_netcount;x++)
		{
		if (FD_ISSET(g_netsocket[x],&tester) == 0) continue;
		process_traffic(&mydb,g_netsocket[x]);
		}
	}

mysql_close(&mydb);
mysql_thread_end();
LogMessage(LOG_INFO,"Thread %d is finished\n",mynum);

return(NULL);
}
/*---------------------------------------------------------------------------*/
void process_traffic(MYSQL *mydb,int netsock)
{
struct client_request	request;
struct sockaddr_in		addr;
unsigned int			len;
char					rxbuffer[1024];
char					txbuffer[1024];
char					textaddr[32];
char					*token,*state;
int						counter;
int						portnum;
int						rxsize;
int						txsize;
int						ret;

// grab the packet from the socket
memset(&addr,0,sizeof(addr));
len = sizeof(addr);
rxsize = recvfrom(netsock,rxbuffer,sizeof(rxbuffer),0,(struct sockaddr *)&addr,&len);
if (rxsize == 0) return;

// non-blocking socket returns EAGAIN error if another thread handled the read
if ((rxsize < 0) && (errno == EAGAIN)) return;

	if (rxsize < 0)
	{
	LogMessage(LOG_WARNING,"Error %d returned from recvfrom()\n",errno);
	return;
	}

// extract the inbound address and check the size
inet_ntop(AF_INET,&addr.sin_addr,textaddr,sizeof(textaddr));
portnum = htons(addr.sin_port);

	if (rxsize >= sizeof(rxbuffer) -1)
	{
	LogMessage(LOG_WARNING,"Invalid message size %d from %s:%d\n", rxsize,textaddr,portnum);
	return;
	}

	// minimum size for a prediction query
	if (rxsize < 4)
	{
	LogMessage(LOG_WARNING,"Incomplete UDP query received from %s:%d\n",textaddr,portnum);
	return;
	}

// make sure the buffer is null terminated
rxbuffer[rxsize] = 0;

LogMessage(LOG_DEBUG,"Message from %s:%d = %s\n",textaddr,portnum,rxbuffer);

// prepare to parse the message
//memset(&request,0,sizeof(request));
request.mydb = mydb;
state = NULL;
counter = 0;

// parse the request using the thread safe version of strtok
// we receive prediction requests in the following format
// version+uid+ipaddr+port+protocol
// 1+00000000-0000-0000-0000-000000000000+192.168.222.5+53+17
	for(token = strtok_r(rxbuffer,"+",&state);token != NULL;token = strtok_r(NULL,"+",&state))
	{
	counter++;
		switch(counter)
		{
		case 1:
			request.version = atoi(token);
			break;
		case 2:
			strncpy(request.uid,token,sizeof(request.uid));
			break;
		case 3:
			strncpy(request.address,token,sizeof(request.address));
			break;
		case 4:
			request.port = atoi(token);
			break;
		case 5:
			request.protocol = atoi(token);
			break;
		}
	}

LogMessage(LOG_DEBUG,"VER:%d UID:%s ADDR:%s PORT:%d PROTO:%d\n",request.version,request.uid,request.address,request.port,request.protocol);

txsize = process_query(&request,txbuffer,sizeof(txbuffer));
	if (txsize == 0)
	{
	strcpy(txbuffer,UNKNOWN_TRAFFIC);
	txsize = strlen(txbuffer);
	}

ret = sendto(netsock,txbuffer,txsize,0,(struct sockaddr *)&addr,sizeof(addr));
	if (ret != txsize)
	{
	LogMessage(LOG_WARNING,"Transmit error sending to %s:%d\n",textaddr,portnum);
	}

LogMessage(LOG_DEBUG,"TRANSMIT: %s\n", txbuffer);
}
/*---------------------------------------------------------------------------*/
int process_query(struct client_request *request,char *target,int length)
{
struct client_response	response;
uint64_t				infoid;
char					qbuffer[2048];
char					*collist;
char					*spot;
int						len,ret;

// see if we have an ip_info_id for the IP address in the request
len = sprintf(qbuffer,"SELECT ip_info_id FROM ip_info WHERE ip = '%s'",request->address);
ret = mysql_real_query(request->mydb,qbuffer,len);
	if (ret != 0)
	{
	database_error(request->mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}

// if nothing found just return
infoid = result_to_value(request->mydb);
if (infoid == 0) return(0);

// search for the most common appid and protochain
collist = "application_control_application,application_control_protochain";
len = sprintf(qbuffer,"SELECT %s FROM routing_info WHERE ip_info_id = %lu AND protocol = %u AND port = %u ORDER BY count LIMIT 1",collist,infoid,request->protocol,request->port);
ret = mysql_real_query(request->mydb,qbuffer,len);
	if (ret != 0)
	{
	database_error(request->mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}
ret = result_to_client(request->mydb,&response);
if (ret == 0) return(0);

// search for the static details for the application
collist = "application_name,application_category,application_productivity,application_risk";
len = sprintf(qbuffer,"SELECT %s FROM application_lookup WHERE application_id = \'%s\' LIMIT 1",collist,response.appid);
ret = mysql_real_query(request->mydb,qbuffer,len);
	if (ret != 0)
	{
	database_error(request->mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}
ret = lookup_to_client(request->mydb,&response);
if (ret == 0) return(0);

target[0] = 0;
spot = target;
spot+=sprintf(spot,"{");
spot+=sprintf(spot,"\"ID\":\"%s\",",response.appid);
spot+=sprintf(spot,"\"Name\":\"%s\",",response.name);
spot+=sprintf(spot,"\"Confidence\":%d,",50);
spot+=sprintf(spot,"\"ProtoChain\":\"%s\",",response.protochain);
spot+=sprintf(spot,"\"Productivity\":%d,",response.productivity);
spot+=sprintf(spot,"\"Risk\":%d,",response.risk);
spot+=sprintf(spot,"\"Category\":\"%s\"",response.category);
spot+=sprintf(spot,"}");
LogMessage(LOG_DEBUG,"RESPONSE = %s\n", target);

return(strlen(target));
}
/*---------------------------------------------------------------------------*/
uint64_t result_to_value(MYSQL *mydb)
{
uint64_t		value;
MYSQL_RES		*data;
MYSQL_ROW		row;

// store the result and bail on error
data = mysql_store_result(mydb);
	if (data == NULL)
	{
	database_error(mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}

// seek to the first row and fetch
mysql_data_seek(data,0);
row = mysql_fetch_row(data);

// get the value from the result if valid
value = 0;
if ((row != NULL) && (row[0] != NULL)) value = strtoull(row[0],NULL,10);

// free the result and return the value
mysql_free_result(data);
return(value);
}
/*---------------------------------------------------------------------------*/
char* result_to_string(MYSQL *mydb,char *target,int length)
{
MYSQL_RES	*data;
MYSQL_ROW	row;
char		*string;

// store the result and bail on error
data = mysql_store_result(mydb);
	if (data == NULL)
	{
	database_error(mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(NULL);
	}

// seek to the first row and fetch
mysql_data_seek(data,0);
row = mysql_fetch_row(data);

// get the string from the result if valid
if ((row != NULL) && (row[0] != NULL)) string = strncpy(target,row[0],length);
else string = NULL;

// free the result and return the value
mysql_free_result(data);
return(string);
}
/*---------------------------------------------------------------------------*/
int result_to_client(MYSQL *mydb,struct client_response *response)
{
MYSQL_RES	*data;
MYSQL_ROW	row;
int			fields;

// store the result and bail on error
data = mysql_store_result(mydb);
	if (data == NULL)
	{
	database_error(mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}

// seek to the first row and fetch
mysql_data_seek(data,0);
row = mysql_fetch_row(data);
	if (row == NULL)
	{
	mysql_free_result(data);
	return(0);
	}

// make sure we have the expected number of fields
fields = mysql_num_fields(data);
	if (fields != 2)
	{
	mysql_free_result(data);
	return(0);
	}

strcpy(response->appid,row[0]);
strcpy(response->protochain,row[1]);

// free the result and return
mysql_free_result(data);
return(5);
}
/*---------------------------------------------------------------------------*/
int lookup_to_client(MYSQL *mydb,struct client_response *response)
{
MYSQL_RES	*data;
MYSQL_ROW	row;
int			fields;

// store the result and bail on error
data = mysql_store_result(mydb);
	if (data == NULL)
	{
	database_error(mydb,__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}

// seek to the first row and fetch
mysql_data_seek(data,0);
row = mysql_fetch_row(data);
	if (row == NULL)
	{
	mysql_free_result(data);
	return(0);
	}

// make sure we have the expected number of fields
fields = mysql_num_fields(data);
	if (fields != 4)
	{
	mysql_free_result(data);
	return(0);
	}

strcpy(response->name,row[0]);
strcpy(response->category,row[1]);
response->productivity = atoi(row[2]);
response->risk = atoi(row[3]);

// free the result and return
mysql_free_result(data);
return(5);
}
/*---------------------------------------------------------------------------*/

