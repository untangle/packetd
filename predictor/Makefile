# Telemetry Traffic Predictor Daemon
# Copyright (c) 2020 Untangle, Inc.
# All Rights Reserved
# Written by Michael A. Hotz

VERSION = 1.0.0
DEBUG = -g3 -ggdb
#GPROF = -pg
#SPEED = -O2

BUILDID := "$(shell date -u "+%G/%m/%d %H:%M:%S UTC")"
SYSTEM := $(shell uname)
ARCH := $(shell uname -m)

ifeq ($(SYSTEM),Linux)
  PLATFORM = -D__LINUX__
  LIBFILES = -lpthread -lrt -lmysqlclient
else
  $(error ERROR: Unsupported platform '$(SYSTEM)')
endif

CPPFLAGS = $(DEBUG) $(GPROF) $(SPEED) -Wall -Wno-deprecated -pthread

CPPFLAGS += -DVERSION=\"$(VERSION)\"
CPPFLAGS += -DBUILDID=\"$(BUILDID)\"
CPPFLAGS += -DPLATFORM=\"$(PLATFORM)\"

OBJFILES := $(patsubst %.c,%.o,$(wildcard *.c))

predictor : $(OBJFILES)
	$(CC) $(DEBUG) $(GPROF) $(SPEED) $(OBJFILES) $(LIBFILES) -o predictor

$(OBJFILES) : Makefile *.h

clean : force
	rm -r -f Debug
	rm -f predictor
	rm -f gmon.out
	rm -f *.vtg
	rm -f *.o

force :

