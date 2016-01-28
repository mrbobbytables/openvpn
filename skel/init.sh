#!/bin/bash

########## OpenVPN ##########
# Init script for openVPN
########## OpenVPN ##########

source /opt/scripts/container_functions.lib.sh

init_vars() {

  if [[ $ENVIRONMENT_INIT && -f $ENVIRONMENT_INIT ]]; then
      source "$ENVIRONMENT_INIT"
  fi 

  if [[ ! $PARENT_HOST && $HOST ]]; then
    export PARENT_HOST="$HOST"
  fi

  export APP_NAME=${APP_NAME:-openvpn}
  export ENVIRONMENT=${ENVIRONMENT:-local}
  export PARENT_HOST=${PARENT_HOST:-unknown}

  export OVPN_AUTOCONF=${OVPN_AUTOCONF:-enabled}
  export OVPN_CONF=${OVPN_CONF:-/etc/openvpn/ovpn.conf}
  export OVPN_IPTB_CREATE=${OVPN_IPTB_CREATE:-/opt/scripts/create-iptb-rules.sh}
  export OVPN_IPTB_DELETE=${OVPN_IPTB_DELETE:-/opt/scripts/delete-iptb-rules.sh}
  export KEEPALIVED_AUTOCONF=${KEEPALIVED_AUTOCONF:-enabled}

  export SERVICE_CONSUL_TEMPLATE=${SERVICE_CONSUL_TEMPLATE:-disabled}
  export SERVICE_RSYSLOG=${SERVICE_RSYSLOG:-enabled}
  export SERVICE_KEEPALIVED_CONF=${SERVICE_KEEPALIVED_CONF:-/etc/keepalived/keepalived.conf}
  export SERVICE_LOGSTASH_FORWARDER_CONF=${SERVICE_LOGSTASH_FORWARDER_CONF:-/opt/logstash-forwarder/ovpn.conf}
  export SERVICE_REDPILL_CLEANUP=${SERVICE_REDPILL_CLEANUP:-"$OVPN_IPTB_DELETE"}
  export SERVICE_REDPILL_MONITOR=${SERVICE_REDPILL_MONITOR:-"ovpn,keepalived"}

  local ovpn_cmd="$(__escape_svsr_txt "/usr/sbin/openvpn --config \"$OVPN_CONF\"")"
  export SERVICE_OVPN_CMD=${SERVICE_OVPN_CMD:-"$ovpn_cmd"}

  case "${ENVIRONMENT,,}" in
    prod|production|dev|development)
      export SERVICE_KEEPALIVED=${SERVICE_KEEPALIVED:-enabled}
      export SERVICE_LOGROTATE=${SERVICE_LOGROTATE:-enabled}
      export SERVICE_LOGSTASH_FORWARDER=${SERVICE_LOGSTASH_FORWARDER:-enabled}
      export SERVICE_REDPILL=${SERVICE_REDPILL:-enabled}
      ;;
    debug)
      export SERVICE_KEEPALIVED=${SERVICE_KEEPALIVED:-enabled}
      export SERVICE_LOGROTATE=${SERVICE_LOGROTATE:-disabled}
      export SERVICE_LOGSTASH_FORWARDER=${SERVICE_LOGSTASH_FORWARDER:-disabled}
      export SERVICE_REDPILL=${SERVICE_REDPILL:-disabled}
      export SERVICE_KEEPALIVED_CMD="/usr/sbin/keepalived -n -D -l -f $SERVICE_KEEPALIVED_CONF"
      export OVPN_VERB=${OVPN_VERB:-11}
      if [[ "$SERVICE_CONSUL_TEMPLATE" == "enabled" ]]; then
        export CONSUL_TEMPLATE_LOG_LEVEL=${CONSUL_TEMPLATE_LOG_LEVEL:-debug}
      fi
      ;;
    local|*)
      export SERVICE_KEEPALIVED=${SERVICE_KEEPALIVED:-disabled} 
      export SERVICE_LOGROTATE=${SERVICE_LOGROTATE:-enabled}
      export SERVICE_LOGSTASH_FORWARDER=${SERVICE_LOGSTASH_FORWARDER:-disabled}
      export SERVICE_REDPILL=${SERVICE_REDPILL:-enabled}
      ;;
  esac
}


add_user_iptables_rules() {
  for rule in $(compgen -A variable | grep -E "IPTB_RULE_[0-9]{1,3}"); do
    echo "iptables -A ${!rule}" >> "$OVPN_IPTB_CREATE"
    echo "iptables -D ${!rule}" >> "$OVPN_IPTB_DELETE"
  done
}


config_iptables() {

  # no catchall (*) as this function should only ever be called after config_ovpn which does test for it.
  case "${OVPN_AUTOCONF,,}" in
    disabled)
      if [[ $(compgen -A variable | grep -E "IPTB_RULE_[0-9]{1,3}") ]]; then
        add_user_iptables_rules
      fi
      chmod +x "$OVPN_IPTB_CREATE"
      chmod +x "$OVPN_IPTB_DELETE"
      ;;
    enabled)
      if [[ ! $(compgen -A variable | grep -E "OVPN_NET_[0-9]{1,3}") ]]; then
        echo "[$(date)][OpenVPN][iptables] No networks to route. OpenVPN Configuration cannot continue."
        return 1
      else
          echo "#!/bin/bash" > "$OVPN_IPTB_CREATE"
          echo "#!/bin/bash" > "$OVPN_IPTB_DELETE"
          echo "# Autocreated iptables creation script." >> "$OVPN_IPTB_CREATE"
          echo "# Autocreated iptables deletion script." >> "$OVPN_IPTB_DELETE"
          chmod +x "$OVPN_IPTB_CREATE"
          chmod +x "$OVPN_IPTB_DELETE"
       
          lstn_int=$(ip addr show | grep "$OVPN_LOCAL" | awk '{print $NF}')
          ovpn_cidr="$(echo "$OVPN_SERVER" | awk '{print $1}')/$(__mask2cidr "$(echo "$OVPN_SERVER" | awk '{print $2}')")"
          echo "iptables -A INPUT -i $lstn_int -d $OVPN_LOCAL -p $OVPN_PROTO --dport $OVPN_PORT -m conntrack --ctstate NEW -j ACCEPT" >> "$OVPN_IPTB_CREATE"
          echo "iptables -D INPUT -i $lstn_int -d $OVPN_LOCAL -p $OVPN_PROTO --dport $OVPN_PORT -m conntrack --ctstate NEW -j ACCEPT" >> "$OVPN_IPTB_DELETE"
          echo "iptables -A INPUT -i tun+ -j ACCEPT" >> "$OVPN_IPTB_CREATE"
          echo "iptables -D INPUT -i tun+ -j ACCEPT" >> "$OVPN_IPTB_DELETE"
          for routed_net in $(compgen -A variable | grep -E "OVPN_NET_[0-9]{1,3}"); do
            net_int="$(echo "${!routed_net}" | sed -r "s|(^.*):([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\/[0-9]{1,2})|\1|")"
            net_cidr="$(echo "${!routed_net}" |  sed -r "s|(^.*):([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\/[0-9]{1,2})|\2|")"
            echo "iptables -A FORWARD -i tun+ -o $net_int -s $ovpn_cidr -d $net_cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" >> "$OVPN_IPTB_CREATE"
            echo "iptables -D FORWARD -i tun+ -o $net_int -s $ovpn_cidr -d $net_cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" >> "$OVPN_IPTB_DELETE"
            echo "iptables -A FORWARD -i $net_int -o tun+ -s $net_cidr -d $ovpn_cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" >> "$OVPN_IPTB_CREATE"
            echo "iptables -D FORWARD -i $net_int -o tun+ -s $net_cidr -d $ovpn_cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" >> "$OVPN_IPTB_DELETE"
            echo "iptables -A POSTROUTING -t nat -o $net_int -s $net_cidr -d $ovpn_cidr -j MASQUERADE" >> "$OVPN_IPTB_CREATE"
            echo "iptables -D POSTROUTING -t nat -o $net_int -s $net_cidr -d $ovpn_cidr -j MASQUERADE" >> "$OVPN_IPTB_DELETE"
          done
          echo "iptables -A OUTPUT -o tun+ -j ACCEPT" >> "$OVPN_IPTB_CREATE"
          echo "iptables -D OUTPUT -o tun+ -j ACCEPT" >> "$OVPN_IPTB_DELETE"
        if [[ $(compgen -A variable | grep -E "IPTB_RULE_[0-9]{1,3}") ]]; then
          add_user_iptables_rules
        fi
      fi
      ;;
  esac
# run delete just in case container previously exited in a bad state stranding some rules
  "$OVPN_IPTB_DELETE"
  "$OVPN_IPTB_CREATE"
  return 0
}


config_ovpn() {

  mkdir -p /dev/net
  if [[ ! -c /dev/net/tun ]]; then
    mknod /dev/net/tun c 10 200
  fi

  case "${OVPN_AUTOCONF,,}" in
    disabled)
      if [[ ! -f $OVPN_CONF ]]; then
        echo "[$(date)][OpenVPN] No Configuration file found at provided location: $OVPN_CONF."
        return 1
      fi
      ;;
    enabled)
      if [[ ! $OVPN_LOCAL ]]; then
        echo "[$(date)][OpenVPN] No local (bind) address specified. Cannot continue with autoconfiguration."
        return 1
      fi
      export OVPN_MODE=${OVPN_MODE:-server}
      export OVPN_CA=${OVPN_CA:-/etc/openvpn/certs/ca.crt}
      export OVPN_CERT=${OVPN_CERT:-/etc/openvpn/certs/server.crt}
      export OVPN_KEY=${OVPN_KEY:-/etc/openvpn/certs/server.key}
      export OVPN_DH=${OVPN_DH:-/etc/openvpn/certs/dh2048.pem}
      export OVPN_CIPHER=${OVPN_CIPHER:-BF-CBC}
      export OVPN_VERB=${OVPN_VERB:-1}
      export OVPN_LOG_APPEND=${OVPN_LOG_APPEND:-/var/log/openvpn/ovpn.log} 
      export OVPN_PORT=${OVPN_PORT:-1194}
      export OVPN_PROTO=${OVPN_PROTO:-udp}
      export OVPN_KEEPALIVE=${OVPN_KEEPALIVE:-"10 120"}
      export OVPN_SERVER=${OVPN_SERVER:-"192.168.253.0 255.255.255.0"}
      
      echo "dev tun" > "$OVPN_CONF"
      echo "comp-lzo" >> "$OVPN_CONF"
      echo "persist-key" >> "$OVPN_CONF"
      echo "persist-tun" >> "$OVPN_CONF"
      echo "user nobody" >> "$OVPN_CONF"
      echo "group nogroup" >> "$OVPN_CONF"
      echo "syslog openvpn" >> "$OVPN_CONF"
      echo "mode $OVPN_MODE" >> "$OVPN_CONF"
      echo "ca $OVPN_CA" >> "$OVPN_CONF"
      echo "cert $OVPN_CERT" >> "$OVPN_CONF"
      echo "key $OVPN_KEY" >> "$OVPN_CONF"
      echo "dh $OVPN_DH" >> "$OVPN_CONF"
      echo "cipher $OVPN_CIPHER" >> "$OVPN_CONF"
      echo "verb $OVPN_VERB" >> "$OVPN_CONF"
      echo "local $OVPN_LOCAL" >> "$OVPN_CONF"
      echo "port $OVPN_PORT" >> "$OVPN_CONF"
      echo "proto $OVPN_PROTO" >> "$OVPN_CONF"
      echo "keepalive $OVPN_KEEPALIVE" >> "$OVPN_CONF"
      echo "server $OVPN_SERVER" >> "$OVPN_CONF"
      for push in $(compgen -A variable | grep -E "OVPN_PUSH_[0-9]{1,3}"); do
        echo "push \"${!push}\"" >> "$OVPN_CONF"
      done
      ;;
    *)
      echo "[$(date)][OpenVPN] Unkown configuration option: \"$OPENVPN_AUTOCONF\". OpenVPN configuration cannot complete."
      return 1
      ;;
  esac 

  config_iptables
  if [[ $? -ne 0 ]]; then
    echo "[$(date)][OpenVPN][iptables] Error encountered configuring iptables. OpenVPN configuration cannot complete."
    return 1
  else
    return 0
  fi
}


main() {

  init_vars

  echo "[$(date)[App-Name] $APP_NAME"
  echo "[$(date)][Environment] $ENVIRONMENT"

  __config_service_consul_template
  __config_service_keepalived
  __config_service_logrotate
  __config_service_logstash_forwarder
  __config_service_redpill
  __config_service_rsyslog

  if [[ ${SERVICE_KEEPALIVED,,} == "enabled" && ${KEEPALIVED_AUTOCONF,,}  == "enabled" ]]; then
    __config_keepalived
    if [[ $? -ne 0 ]]; then
      echo "[$(date)][Keepalived] Error configuring keepalived. Terminating init."
      exit 1
    fi
  fi

  config_ovpn
  if [[ $? -ne 0 ]]; then
    echo "[$(date)][OpenVPN] Error while configuring OpenVPN. Terminating init."
    exit 1
  fi

  echo "[$(date)][OpenVPN][Start-Command] $SERVICE_OVPN_CMD"

  exec supervisord -n -c /etc/supervisor/supervisord.conf

}

main "$@"
