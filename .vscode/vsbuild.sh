#!/bin/bash
##
## Build mfw admin UI
##
TARGET=$1

docker-compose -f build/docker-compose.build.yml up --build musl
ssh root@$TARGET "/etc/init.d/packetd stop"; 
sleep 5
scp ./cmd/packetd/packetd root@$TARGET:/usr/bin/; 
ssh root@$TARGET "/etc/init.d/packetd start"

