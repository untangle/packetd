#!/bin/sh
 
if [ "" = "$1" ] ; then
    echo "usage: $0 report_filename.json"
    exit 1
fi

REPORT_FILE=$1

QUERY_ID="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d @./${REPORT_FILE} 'http://localhost/api/reports/create_query'`"
echo $QUERY_ID

DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost/api/reports/get_data/$QUERY_ID"`"
echo $DATA
