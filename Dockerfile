################################################################################
# openvpn:1.2.0
# Date: 1/22/2016
# OpenVPN Version: 2.3.2-7ubuntu3.1
# Keepalived Version: 1:1.2.7-1ubuntu1
#
# Description:
# Provide secure access to the Mesos Network with additional high availability
# from keepalived.
################################################################################

FROM mrbobbytables/ubuntu-base:1.1.0
MAINTAINER Bob Killen / killen.bob@gmail.com / @mrbobbytables


ENV VERSION_OPENVPN=2.3.2-7ubuntu3.1  \
    VERSION_KEEPALIVED=1:1.2.7-1ubuntu1

RUN apt-get update      \
 && apt-get -y install  \
    iptables            \
    keepalived=$VERSION_KEEPALIVED     \
    openvpn=$VERSION_OPENVPN           \
 && apt-get -y autoremove              \
 && apt-get -y autoclean               \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY ./skel  /

RUN chmod +x ./init.sh            \
 && chmod 640 /etc/logrotate.d/*  \
 && chown -R logstash-forwarder:logstash-forwarder /opt/logstash-forwarder


CMD ["./init.sh"]
