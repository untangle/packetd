#!/bin/bash
##
## Build mfw packetd
##
TARGET=$1
PORT=22
LOCAL_MUSL_BUILD=false

while getopts 't:p:m:' flag; do
    case "${flag}" in
        t) TARGET=${OPTARG} ;;
        p) PORT=${OPTARG} ;;
        m) LOCAL_MUSL_BUILD=${OPTARG} ;;
    esac
done
shift $((OPTIND-1))

if [ LOCAL_MUSL_BUILD ]
then
    docker-compose -f build/docker-compose.build.yml up --build musl-local
else
    docker-compose -f build/docker-compose.build.yml up --build musl
fi

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $PORT root@$TARGET "/etc/init.d/packetd stop"; 
sleep 5
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $PORT ./cmd/packetd/packetd root@$TARGET:/usr/bin/; 
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $PORT root@$TARGET "/etc/init.d/packetd start"

