[![Build Status](https://travis-ci.org/untangle/packetd.svg?branch=master)](https://travis-ci.org/untangle/packetd)

# packetd
Userspace packet processing daemon

# packages required to build
apt-get install libnetfilter-log-dev libnetfilter-queue-dev libnetfilter-conntrack-dev

# packages required to run
apt-get install untangle-classd untangle-geoip-database untangle-python3-sync-settings libnetfilter-log1 libnetfilter-queue1 libnetfilter-conntrack3

To build:
go build

For golint:
go get -u golang.org/x/lint/golint
then
golint ~/go/src/github.com/untangle/packetd/...

