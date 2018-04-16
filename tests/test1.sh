#!/bin/sh

QUERY_ID="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d @./test1-report.json 'http://localhost:8080/reports/create_query'`"
echo $QUERY_ID

#DATA="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d $QUERY_ID 'http://localhost:8080/reports/get_data'`"
#echo $DATA

#DATA="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d $QUERY_ID 'http://localhost:8080/reports/get_data'`"
#echo $DATA

DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/reports/get_data/$QUERY_ID"`"
echo $DATA
