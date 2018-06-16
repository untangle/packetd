[![Build Status](https://travis-ci.org/untangle/packetd.svg?branch=master)](https://travis-ci.org/untangle/packetd)
[![Go Report Card](https://goreportcard.com/badge/github.com/untangle/packetd)](https://goreportcard.com/report/github.com/untangle/packetd)
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
go build
```

Building in docker
==================

For this to work you *have* to have your clone under a path of the form:

```
[...]/src/github.com/untangle/packetd
```

libc target
-----------

```
docker-compose -f docker-compose.build.yml up --build libc
```

Result:

```
# file ./packetd
./packetd: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7459d11c6fd1dd3ed5d3e3ed5c2320e27dc4bea4, with debug_info, not stripped
```

MUSL target
-----------

```
docker-compose -f docker-compose.build.yml up --build musl
```

Result:

```
# file ./packetd
./packetd: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, with debug_info, not stripped
```

Running it
==========

You'll also need an Untangle mirror for most of those:

```
apt-get install untangle-classd untangle-geoip-database untangle-python3-sync-settings libnetfilter-log1 libnetfilter-queue1 libnetfilter-conntrack3
```

Then:

```
./packetd
```

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
