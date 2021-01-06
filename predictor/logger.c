// Untangle Traffic Predictor Daemon
// Copyright (c) 2020 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "predictor.h"
/*---------------------------------------------------------------------------*/
void LogMessage(int level,const char *format,...)
{
va_list			args;
char			*message;
int				memsize;
int				ret;

if ((level == LOG_DEBUG) && (cfg_debug == 0)) return;

// allocate a buffer for the formatted message
memsize = 4096;
message = (char *)malloc(memsize);

// write the formatted output to the buffer
va_start(args,format);
ret = vsnprintf(message,memsize,format,args);
va_end(args);

	// if buffer was too small reallocate and try again
	if (ret >= memsize)
	{
	memsize = (ret + 1);
	message = (char *)realloc(message,memsize);
	va_start(args,format);
	ret = vsnprintf(message,memsize,format,args);
	va_end(args);
	}

// write the formatted message and free memory
WriteMessage(level,message);
free(message);
}
/*---------------------------------------------------------------------------*/
void LogBinary(int level,const char *info,const void *buffer,int length)
{
const unsigned char		*data;
char					*message;
char					*spot;
int						size,x;

if ((level == LOG_DEBUG) && (cfg_debug == 0)) return;

// allocate a new logger message object
size = ((length * 3) + 2);
if (info != NULL) size+=strlen(info);
message = (char *)malloc(size);

// create a text string of XX values
data = (const unsigned char *)buffer;
spot = message;
if (info != NULL) spot+=sprintf(spot,"%s",info);
for(x = 0;x < length;x++) spot+=sprintf(spot,"%02hhX ",data[x]);
spot+=sprintf(spot,"%s","\n");

// write the formatted message and free memory
WriteMessage(level,message);
free(message);
}
/*---------------------------------------------------------------------------*/
void WriteMessage(int level,const char *message)
{
struct timeval		nowtime;
double				rr,nn,ee;
char				elapsed[32];

	if (cfg_console == 0)
	{
	syslog(level,"%s",message);
	return;
	}

gettimeofday(&nowtime,NULL);

rr = ((double)g_runtime.tv_sec * (double)1000000.00);
rr+=(double)g_runtime.tv_usec;

nn = ((double)nowtime.tv_sec * (double)1000000.00);
nn+=(double)nowtime.tv_usec;

ee = ((nn - rr) / (double)1000000.00);

VALUEtoLEVEL(level,elapsed);

pthread_mutex_lock(&g_loggerlock);
fprintf(stdout,"[%.6f] %s ",ee,elapsed);
fputs(message,stdout);
pthread_mutex_unlock(&g_loggerlock);

fflush(stdout);
}
/*---------------------------------------------------------------------------*/
char* VALUEtoLEVEL(int value,char *dest)
{
if (value == LOG_EMERG)		return(strcpy(dest,"EMERGENCY"));
if (value == LOG_ALERT)		return(strcpy(dest,"ALERT"));
if (value == LOG_CRIT)		return(strcpy(dest,"CRITICAL"));
if (value == LOG_ERR)		return(strcpy(dest,"ERROR"));
if (value == LOG_WARNING)	return(strcpy(dest,"WARNING"));
if (value == LOG_NOTICE)	return(strcpy(dest,"NOTICE"));
if (value == LOG_INFO)		return(strcpy(dest,"INFO"));
if (value == LOG_DEBUG)		return(strcpy(dest,"DEBUG"));
sprintf(dest,"LOG_%d",value);
return(dest);
}
/*---------------------------------------------------------------------------*/

