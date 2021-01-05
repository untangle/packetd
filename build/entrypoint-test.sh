#! /bin/bash

set -e

LIBC=${1:-glibc}

# remove libc markers from our binaries' names
for f in $(ls /usr/bin/*-$LIBC 2> /dev/null) ; do
  cp $f ${f/-${LIBC}}
done

settingsd &

# this fails to start right now
#packetd

# Sometimes curl runs before settingsd/gin is ready to listen for connections
sleep 3

# /static without the trailing slash gives a 301, which curl -f
# considers a success
curl -f http://localhost/static
