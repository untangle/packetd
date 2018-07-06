#!/bin/sh -x

echo 1 > /proc/sys/net/ipv4/ip_forward

nft add table nat
nft add chain nat prerouting "{ type nat hook prerouting priority -100 ; }"
nft add chain nat postrouting "{ type nat hook postrouting priority 100 ; }"
nft add rule nat postrouting counter masquerade

