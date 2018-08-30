#!/bin/sh -x

echo 1 > /proc/sys/net/ipv4/ip_forward

modprobe nft_chain_nat_ipv4
modprobe nft_chain_nat_ipv6

nft add table ip postrouting
nft add table ip prerouting

nft add chain ip postrouting postrouting-nat "{ type nat hook postrouting priority 100 ; }"
nft add chain ip prerouting  prerouting-nat "{ type nat hook prerouting priority -100 ; }"

nft add rule ip postrouting postrouting-nat oifname lo accept
nft add rule ip postrouting postrouting-nat iifname lo accept
nft add rule ip postrouting postrouting-nat counter masquerade





