[![Build Status](https://travis-ci.org/untangle/packetd.svg?branch=master)](https://travis-ci.org/untangle/packetd)
[![Go Report Card](https://goreportcard.com/badge/github.com/untangle/packetd)](https://goreportcard.com/report/github.com/untangle/packetd)
[![GoDoc](https://godoc.org/github.com/untangle/packetd?status.svg)](https://godoc.org/github.com/untangle/packetd)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

# packetd
Userspace packet processing daemon

Building locally
================

You'll need an Untangle mirror to get the patched libnetfilter-queue-dev:

```
apt-get install libnetfilter-log-dev libnetfilter-queue-dev libnetfilter-conntrack-dev
```

Then build the regular way:

```
make
```

This will install several dependencies automatically, or you can do so manually:

```
go get -u github.com/gin-gonic/gin
go get -u github.com/gin-contrib/cors
go get -u github.com/gin-contrib/contrib
go get -u github.com/gin-contrib/location
go get -u github.com/gin-contrib/sessions
go get -u github.com/gorilla/context
go get -u github.com/gorilla/sessions
go get -u github.com/gorilla/securecookie
go get -u github.com/google/gopacket
go get -u github.com/mattn/go-sqlite3
go get -u github.com/oschwald/geoip2-golang
go get -u github.com/GehirnInc/crypt
go get -u github.com/c9s/goprocinfo/linux

```

If you want to use the golint tool, you can install it with this command:
```
go get -u golang.org/x/lint/golint
```

You can run golint with the following command: (assumes GOPATH=~/golang)

```
~/golang/bin/golint github.com/untangle/packetd/...
```

Building in docker
==================

For this to work you *have* to have your clone under a path of the form:

```
[...]/src/github.com/untangle/packetd
```

MUSL target
-----------

```
docker-compose -f build/docker-compose.build.yml up --build musl
```

Result:

```
# file ./cmd/packetd/packetd
./packetd: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, with debug_info, not stripped
```

glibc target
-----------

```
docker-compose -f build/docker-compose.build.yml up --build glibc
```

Result:

```
# file ./cmd/packetd/packetd
./packetd: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7459d11c6fd1dd3ed5d3e3ed5c2320e27dc4bea4, with debug_info, not stripped
```

Running it locally
==================

You'll also need an Untangle mirror for most of those:

```
apt-get install untangle-classd untangle-geoip-database untangle-python3-sync-settings libnetfilter-log1 libnetfilter-queue1 libnetfilter-conntrack3 nftables
```

Then:

```
./packetd
```

Running in an OpenWrt container
===============================

Getting the image
-----------------

They're at https://hub.docker.com/r/untangleinc/mfw/tags

```
docker pull untangleinc/mfw:x86-64
```

You can also build one yourself:

```
git clone https://github.com/untangle/mfw_build.git
cd mfw_build
curl -o x86-64-rootfs.tar.gz http://jenkins.untangle.int/.../artifacts/openwrt-x86-64-generic-rootfs_openwrt-18.06_<timestamp>.tar.gz
docker build -f Dockerfile.test.mfw --build-arg ROOTFS_TARBALL=x86-64-rootfs.tar.gz -t untangleinc/mfw:x86-64_my-own-image .
```

Running a container from it
---------------------------

```
docker run -it --rm untangleinc/mfw:x86-64_20190207
```

Getting a shell in that container
---------------------------------

In another terminal:

```
# docker ps | grep mfw
fe6947926f3f        untangleinc/mfw:x86-64_20190207   "/sbin/init"             7 seconds ago       Up 6 seconds        22/tcp              optimistic_haslett
# docker exec -it fe6947926f3f sh

BusyBox v1.28.4 () built-in shell (ash)

/ # ps w
  PID USER       VSZ STAT COMMAND
    1 root     13316 S    /sbin/procd
   77 root      8988 S    /sbin/ubusd
  244 root      7048 S    /sbin/logd -S 64
  603 root     15540 S    /sbin/netifd
  689 root      2900 S    /usr/sbin/dropbear -F -P /var/run/dropbear.1.pid -p 22 -K 300 -T 3
  704 root     11224 S    /usr/sbin/odhcpd
  818 root      3084 S    udhcpc -p /var/run/udhcpc-eth0.pid -s /lib/netifd/dhcp.script -f -t 0 -i eth0 -x hostname:fe6947926f3f -C
  824 root      4856 S    odhcp6c -s /lib/netifd/dhcpv6.script -P0 -t120 eth0
 1176 root      3084 S    sh
 1192 root      3084 R    ps w
```

Copying a new packetd inside that container
-------------------------------------------

```
docker cp cmd/packetd/packetd fe6947926f3f:/usr/bin/packetd
```

Make sure your packetd binary is build against MUSL, or it won't be able
to run in the MFW container: see "Building in Docker -> MUSL target"
above.

golint
======

Get golint:

```
go get -u golang.org/x/lint/golint
```

Use it:

```
${GOPATH}/bin/golint $(pwd)/...
```
