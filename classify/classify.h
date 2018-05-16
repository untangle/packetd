/**
 * classify.h
 *
 * Passes traffic to Sandvine library for classification
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include "navl.h"

#define CLIENT_to_SERVER	0
#define SERVER_to_CLIENT	1
#define INVALID_VALUE		1234567890
/*--------------------------------------------------------------------------*/
extern void plugin_navl_callback(char *appname,char *protochain,unsigned int ctid);
extern void plugin_attr_callback(char *detail,unsigned int ctid);
/*--------------------------------------------------------------------------*/
int navl_callback(navl_handle_t handle,navl_result_t result,navl_state_t state,navl_conn_t conn,void *arg,int error);
void attr_callback(navl_handle_t handle,navl_conn_t conn,int attr_type,int attr_length,const void *attr_value,int attr_flag,void *arg);
int vendor_classify(const unsigned char *data,int length, unsigned int ctid);
int vendor_log_message(const char *level, const char *func, const char *format, ... );
void vendor_externals(void);
int vendor_config(const char *key,int value);
int vendor_startup(void);
void vendor_shutdown(void);
/*--------------------------------------------------------------------------*/
