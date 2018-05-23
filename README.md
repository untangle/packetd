# packetd
Userspace packet processing daemon

# required packages
apt-get install libnetfilter-log-dev libnetfilter-queue-dev libnetfilter-conntrack-dev
# for libnavl:
apt-get install untangle-classd
# lor geoip:
apt-get install untangle-geoip-database

To build:
go build

For golint:
go get -u golang.org/x/lint/golint
then
golint ~/go/src/github.com/untangle/packetd/...

