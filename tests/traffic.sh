#!/bin/sh

#
# Examples of calling the restd functions for traffic playback and control
#

# Turn on the live traffic bypass flag
RESULT="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{"bypass":"TRUE"}' 'http://localhost/api/control/traffic'`"
echo $RESULT

# Playback a traffic capture a 2x speed
RESULT="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{"filename":"/tmp/warehouse.cap","speed":"2"}' 'http://localhost/api/warehouse/playback'`"
echo $RESULT

# Turn off the live traffic bypass flag
RESULT="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{"bypass":"FALSE"}' 'http://localhost/api/control/traffic'`"
echo $RESULT
