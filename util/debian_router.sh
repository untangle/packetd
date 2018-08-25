#!/bin/sh -x

echo 1 > /proc/sys/net/ipv4/ip_forward

modprobe nft_chain_nat_ipv4
modprobe nft_chain_nat_ipv6

nft add table ip nat
nft add chain ip nat prerouting-nat "{ type nat hook prerouting priority -100 ; }"
nft add chain ip nat postrouting-nat "{ type nat hook postrouting priority 100 ; }"
nft flush chain ip nat postrouting-nat
nft flush chain ip nat prerouting-nat
nft add rule ip nat postrouting-nat oifname lo return
nft add rule ip nat postrouting-nat iifname lo return
nft add rule ip nat postrouting-nat counter masquerade

nft add table ip6 nat
nft add chain ip6 nat prerouting-nat "{ type nat hook prerouting priority -100 ; }"
nft add chain ip6 nat postrouting-nat "{ type nat hook postrouting priority 100 ; }"
nft flush chain ip6 nat postrouting-nat
nft flush chain ip6 nat prerouting-nat

nft add table inet filter
nft add chain inet filter forward-filter "{ type filter hook forward priority 0 ; }"
nft add chain inet filter input-filter "{ type filter hook input priority 0 ; }"
nft add chain inet filter output-filter "{ type filter hook output priority 0 ; }"



