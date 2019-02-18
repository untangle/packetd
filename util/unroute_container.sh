#!/bin/sh

ip route flush table 1000
ip route del default via 172.51.0.2 table main
