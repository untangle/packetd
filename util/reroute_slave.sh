#!/bin/sh

pid=$(sudo docker inspect -f '{{.State.Pid}}' packetd_slave_1)
sudo mkdir -p /var/run/netns
sudo ln -s /proc/$pid/ns/net /var/run/netns/$pid
sudo ip netns exec $pid ip route del default 
sudo ip netns exec $pid ip route add default via 172.51.0.2
