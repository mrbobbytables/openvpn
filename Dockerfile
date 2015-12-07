################################################################################
# openvpn:1.0.0
# Date: 9/27/2015
# OpenVPN Version: 2.3.2-7ubuntu3.1
# Keepalived Version: 1:1.2.7-1ubuntu1
#
# Description:
# Provide secure access to the Mesos Network with additional high availability
# from keepalived.
################################################################################

FROM mrbobbytables/ubuntu-base:1.0.2
MAINTAINER Bob Killen / killen.bob@gmail.com / @mrbobbytables


ENV VERSION_OPENVPN=2.3.2-7ubuntu3.1  \
    VERSION_KEEPALIVED=1:1.2.7-1ubuntu1

RUN apt-get update      \
 && apt-get -y install  \
    iptables            \
    vim \
    keepalived=$VERSION_KEEPALIVED     \
    openvpn=$VERSION_OPENVPN           \
 && apt-get -y autoremove              \
 && apt-get -y autoclean               \
 && rm /etc/rsyslog.d/50-default.conf  \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY ./skel  /

RUN chmod +x ./init.sh         \
 && chown -R logstash-forwarder:logstash-forwarder /opt/logstash-forwarder


CMD ["./init.sh"]
