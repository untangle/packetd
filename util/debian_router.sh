#!/bin/sh -x

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct

modprobe nft_chain_nat_ipv4
modprobe nft_chain_nat_ipv6

nft flush table ip nat 2>/dev/null || true
nft add table ip nat

nft add chain ip nat  postrouting-nat "{ type nat hook postrouting priority 100 ; }"
nft add chain ip nat  prerouting-nat  "{ type nat hook prerouting priority -100 ; }"

nft add rule ip nat postrouting-nat oifname lo accept
nft add rule ip nat postrouting-nat iifname lo accept
nft add rule ip nat postrouting-nat counter masquerade




