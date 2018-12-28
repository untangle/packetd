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

#include "common.h"

const char		*logsrc = "warehouse";
const char		*fileSignature = "UTPDCF";
const uint		majorVersion = 2;
const uint		minorVersion = 0;

static FILE		*capfile = NULL;

struct file_header {
	char			description[48];
	char			signature[8];
	u_int32_t		majver;
	u_int32_t		minver;
};

struct data_header {
	char			origin;
	u_int64_t		stamp_sec;
	u_int32_t		stamp_nsec;
	u_int32_t		length;
	u_int32_t		mark;
	u_int32_t		ctid;
	u_int32_t		nfid;
};

void start_warehouse_capture(void)
{
	struct file_header		header;

	logmessage(LOG_INFO,logsrc,"Beginning capture %s\n",get_warehouse_file());

	// if the capture file is already open close it first
	if (capfile != NULL) fclose(capfile);

	// create the capture file
	capfile = fopen(get_warehouse_file(),"wb");

	// create the file header and write it to the capture file
	memset(&header,0,sizeof(header));
	strcpy(header.description,"Untangle Packet Daemon Traffic Capture\r\n");
	strcpy(header.signature,fileSignature);
	header.majver = majorVersion;
	header.minver = minorVersion;
	fwrite(&header,sizeof(header),1,capfile);
}

void close_warehouse_capture(void)
{
	logmessage(LOG_INFO,logsrc,"Finished capture %s\n",get_warehouse_file());
	if (capfile != NULL) fclose(capfile);
	capfile = NULL;
}

void warehouse_capture(const char origin,void *buffer,uint32_t length,uint32_t mark,uint32_t ctid,uint32_t nfid)
{
	struct data_header		dh;
	struct timespec			now;

	if (get_shutdown_flag() != 0) return;
	if (capfile == NULL) return;

	clock_gettime(CLOCK_MONOTONIC,&now);
	dh.stamp_sec = now.tv_sec;
	dh.stamp_nsec = now.tv_nsec;
	dh.origin = origin;
	dh.length = length;
	dh.mark = mark;
	dh.ctid = ctid;
	dh.nfid = nfid;
	fwrite(&dh,sizeof(dh),1,capfile);
	fwrite(buffer,length,1,capfile);
}

void warehouse_playback(void)
{
	struct conntrack_info	*ctptr;
	struct netlogger_info	*nlptr;
	struct file_header		fh;
	struct data_header		dh;
	struct timespec			frame;
	struct timespec			pause;
	struct timespec			last;
	struct timespec			remain;
	char					*filename;
	char					*buffer;
	FILE					*data;
	size_t					found;
	int						speed;

	filename = get_warehouse_file();

	// open the capture file
	data = fopen(filename,"rb");
	if (data == NULL) {
		logmessage(LOG_WARNING,logsrc,"Unable to playback %s\n",filename);
		return;
	}

	// read the file header
	found = fread(&fh,1,sizeof(fh),data);

    // handle EOF
    if (found == 0) {
		fclose(data);
		return;
    }

	// make sure we got a full header
	if (found != sizeof(fh)) {
		logmessage(LOG_WARNING,logsrc,"Invalid size reading file header %d\n",found);
		fclose(data);
		return;
	}

	if (strncmp(fh.signature,fileSignature,strlen(fileSignature)) != 0) {
		logmessage(LOG_WARNING,logsrc,"Invalid signature in %s\n",filename);
		fclose(data);
		return;
	}

	// check the file version
	if ((fh.majver != majorVersion) || (fh.minver != minorVersion)) {
		logmessage(LOG_WARNING,logsrc,"Invalid capture file version %d.%d\n",fh.majver,fh.minver);
		fclose(data);
		return;
	}

	speed = get_warehouse_speed();
	last.tv_sec = 0;
	last.tv_nsec = 0;

	logmessage(LOG_INFO,logsrc,"Beginning playback %s version %d.%d speed %d%%\n",filename,fh.majver,fh.minver,speed);

	while (feof(data) == 0)
	{
		// read the packet header from the file
		found = fread(&dh,1,sizeof(dh),data);

        // EOF
        if (found == 0) {
            break;
        }

		if (found != sizeof(dh)) {
			logmessage(LOG_WARNING,logsrc,"Invalid size reading packet header %d\n",found);
			break;
		}

		// make sure the length is reasonable
		if ((dh.length < 0x0001) || (dh.length > 0xFFFF)) {
			logmessage(LOG_WARNING,logsrc,"Invalid capture packet length %d\n",dh.length);
			break;
		}

		// allocate a buffer for the data and set the convenience pointers
		buffer = malloc(dh.length);

		if (buffer == NULL) {
			logmessage(LOG_ERR,logsrc,"Unable to allocate memory for playback\n");
			break;
		}

		ctptr = (struct conntrack_info *)buffer;
		nlptr = (struct netlogger_info *)buffer;

		// read the packet data from the file
		found = fread(buffer,1,dh.length,data);
		if (found != dh.length) break;

		// if last is not set this is the first packet so no sleep needed otherwise we calculate
		// the difference between the last and current timestamp and pause for that long
		if ((last.tv_sec == 0) && (last.tv_nsec == 0)) {
			pause.tv_sec = 0;
			pause.tv_nsec = 0;
		} else {
			frame.tv_sec = dh.stamp_sec;
			frame.tv_nsec = dh.stamp_nsec;
			pause = calculate_pause(last,frame,speed);
		}

		// set the last timestamp to the packet timestamp so we can calculate pause for next packet
		last.tv_sec = dh.stamp_sec;
		last.tv_nsec = dh.stamp_nsec;

		// only sleep if speed is not zero and the pause is not zero
		// FIXME - we currently ignore the remain value which would only be valid if the call is interrupted but do we even care?
		if ((speed > 0) && ((pause.tv_sec != 0) || (pause.tv_nsec != 0))) {
			nanosleep(&pause,&remain);
		}

		switch(dh.origin)
		{
			case 'Q':
				dh.ctid |= 0xF0000000;
				go_nfqueue_callback(dh.mark,buffer,dh.length,dh.ctid,dh.nfid,buffer,1,0);
				break;

			case 'C':
				ctptr->conn_id |= 0xF0000000;
				go_conntrack_callback(ctptr,1);
				free(buffer);
				break;

			case 'L':
				go_netlogger_callback(nlptr,1);
				free(buffer);
				break;

			default:
				logmessage(LOG_ERR,logsrc,"Invalid origin packet: %c\n",dh.origin);
		}
	}

	fclose(data);
	set_warehouse_flag('I');
	logmessage(LOG_INFO,logsrc,"Finished playback %s\n",filename);
}

struct timespec calculate_pause(struct timespec start,struct timespec end,int speed)
{
	struct timespec		calc;
	u_int64_t         	value;

	// if playback speed is zero return zero
	if (speed == 0) {
		calc.tv_sec = 0;
		calc.tv_nsec = 0;
		return(calc);
	}

	if ((end.tv_nsec - start.tv_nsec) < 0) {
		calc.tv_sec = end.tv_sec - start.tv_sec - 1;
		calc.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
	} else {
		calc.tv_sec = end.tv_sec - start.tv_sec;
		calc.tv_nsec = end.tv_nsec - start.tv_nsec;
	}

	// if playback speed is 100 return the exact difference
	if (speed == 100) return(calc);

	// FIXME - using a 64 bit variable may cause problems if the calculated pause is
	// large because timespec uses 64 bits for seconds and 32 bits for nanoseconds

	// playback speed is not 100 so calculate the pause using the speed as percentage
	value = ((calc.tv_sec * 1000000000) + calc.tv_nsec);
	value = (value * 100);
	value = (value / speed);

	calc.tv_sec = (value / 1000000000);
	calc.tv_nsec = (value % 1000000000);
	return(calc);
}
