/**
* warehouse.c
*
* Group of functions to capture and playback raw data from the
* nfqueue, conntrack, and netlogger handlers for use in testing
* and disgnostics.
*
* Copyright (c) 2018 Untangle, Inc.
* All Rights Reserved
*/

// TODO - open the capture file on startup and close on shutdown
// TODO - add support for setting playback speed multiplier
// TODO - get the capture and playback file names from command line arguments

#include "common.h"

static char		*logsrc = "warehouse";

struct data_header {
	char			origin;
	u_int64_t		stamp;
	u_int32_t		length;
	u_int32_t		mark;
	u_int32_t		ctid;
	u_int32_t		nfid;
};

int warehouse_startup(void)
{
	return(0);
}

void warehose_shutdown(void)
{
}

void warehouse_capture(const char origin,void *buffer,uint32_t length,uint32_t mark,uint32_t ctid,uint32_t nfid)
{
	struct data_header		dh;
	struct timespec			ts;
	FILE					*data;

	if (get_shutdown_flag() != 0) return;

	clock_gettime(CLOCK_MONOTONIC,&ts);
	dh.stamp = (((uint64_t)1000000000 * (uint64_t)ts.tv_sec) + (uint64_t)ts.tv_nsec);
	dh.origin = origin;
	dh.length = length;
	dh.mark = mark;
	dh.ctid = ctid;
	dh.nfid = nfid;
	data = fopen("/tmp/warehouse.cap","ab");
	fwrite(&dh,sizeof(dh),1,data);
	fwrite(buffer,length,1,data);
	fclose(data);
}

void warehouse_playback(char *filename)
{
	struct conntrack_info	*cinfo;
	struct netlogger_info   *linfo;
	struct data_header		dh;
	char					*buffer;
	int						buflen;
	FILE					*data;
	size_t					found;
	uint64_t				pause;
	uint64_t				last;

	cinfo = (struct conntrack_info *)&buffer;
	linfo = (struct netlogger_info *)&buffer;

	data = fopen(filename,"rb");
	if (data == NULL) {
		logmessage(LOG_WARNING,logsrc,"Unable to playback %s\n",filename);
		return;
	}

	buflen = 4096;
	buffer = malloc(buflen);
	last = 0;

	logmessage(LOG_INFO,logsrc,"Beginning playback %s\n",filename);

	for(;;)
	{
		if (feof(data) != 0) break;

		found = fread(&dh,1,sizeof(dh),data);
		if (found != sizeof(dh)) break;

		if (dh.length > buflen) {
			buffer = realloc(buffer,dh.length);
			buflen = dh.length;
			}

		found = fread(buffer,1,dh.length,data);
		if (found != dh.length) break;

		if (last != 0) pause = (dh.stamp - last);
		else pause = 0;
		last = dh.stamp;
		if (pause > 0) usleep(pause / 1000);

		switch(dh.origin)
		{
			case 'Q':
				go_nfqueue_callback(dh.mark,buffer,dh.length,dh.ctid,dh.nfid,NULL);
				break;

			case 'C':
				go_conntrack_callback(cinfo);
				break;

			case 'L':
				go_netlogger_callback(linfo);
				break;

			default:
				logmessage(LOG_ERR,logsrc,"Invalid origin packet: %c\n",dh.origin);
		}
	}

	fclose(data);
	free(buffer);
	logmessage(LOG_INFO,logsrc,"Finished playback %s\n",filename);

	// we have to free the filename since it was allocated with CString
	free(filename);
}
