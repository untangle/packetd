#!/bin/sh
clear
cat $0
exit 0

#
# Examples of calling the restd functions for traffic bypass control, capture, and playback
#

# Turn on the live traffic bypass flag
curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{"bypass":"TRUE"}' http://localhost/api/control/traffic

# Turn off the live traffic bypass flag
curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{"bypass":"FALSE"}' http://localhost/api/control/traffic


# Start traffic capture
curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{"filename":"/tmp/warehouse.cap"}' http://localhost/api/warehouse/capture

# Close traffic capture
curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' http://localhost/api/warehouse/close


# Playback a traffic capture a 2x speed
curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{"filename":"/tmp/warehouse.cap","speed":"2"}' http://localhost/api/warehouse/playback

# Get the warehouse status
# IMPORTANT:  You should call this function every couple seconds during playback and wait
# for the result to transition from PLAYBACK to IDLE. When that happens you should call
# the cleanup function to purge sessions and free memory allocated during playback.
curl -X GET -s -o - http://localhost/api/warehouse/status

# Cleanup after traffic playback
curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' http://localhost/api/warehouse/cleanup

