FROM untangleinc/packetd:build

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y untangle-python3-sync-settings untangle-geoip-database

# FIXME: target OS not correct right now
RUN mkdir /etc/config
RUN touch /etc/init.d/network

COPY packetd packetd_rules /usr/bin/

EXPOSE 8080

ENTRYPOINT packetd_rules ; packetd
