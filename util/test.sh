#!/bin/sh -x

nft add table filter
nft add chain filter mangle "{ type filter hook prerouting priority -150 ; }"

