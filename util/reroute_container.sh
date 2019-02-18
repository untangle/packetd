#!/bin/sh

GATEWAY=`ip route show table main | awk '/default/ {print $3}'`

echo "Sending traffic containers to real gateway: ${GATEWAY} "
docker network ls | tail -n +2 | awk '{print $1}' | while read ID ; do
    NETID=`docker network inspect ${ID} | grep '"Id"' | sed 's/.*: "\(.*\)",/\1/g' | cut -c -12`
    ip rule add priority 1000 dev br-$NETID table 1000
    echo -e "."
done
echo ""
ip route add default via ${GATEWAY} table 1000

echo "Replacing original gateway ${GATEWAY} with container 172.51.0.2"
ip rule add priority 32000 table 2000
ip route add default via 172.51.0.2 table 2000

