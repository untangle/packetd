#!/bin/sh

GATEWAY=`ip route show table main | awk '/default/ {print $3}'`

if [ "$GATEWAY" = "172.51.0.2" ] ; then
    echo "Traffic already rerouted"
    exit 1
fi

echo "Sending traffic containers to real gateway: ${GATEWAY} "
docker network ls | tail -n +2 | awk '{print $1}' | while read ID ; do
    NETID=`docker network inspect ${ID} | grep '"Id"' | sed 's/.*: "\(.*\)",/\1/g' | cut -c -12`
    ip rule add priority 1000 dev br-$NETID table 1000
    /bin/echo -n "."
done
echo ""
ip route add default via ${GATEWAY} table 1000

echo "Replacing original gateway ${GATEWAY} with container 172.51.0.2"
ip route del default via ${GATEWAY} table main
ip route add default via 172.51.0.2 table main

echo "Moving real default route"
ip route add default via ${GATEWAY} table default

