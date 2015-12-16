# - OpenVPN -
An Ubuntu container built with the purpose of offering a highly available OpenVPN server.

High availability is provided via Keepalived; a well-proven and battle-tested routing and failover service. The main reason for using Keepalived in addition to Marathon's own HA is to account for scenarios where Mesos/Marathon itself may be having issues (e.g. cluster net-splits) and access is still needed to the private Mesos-Network.

With services such as OpenVPN where a container needs to modify the host configuration to function (in this case iptables rules); Redpill provides the essential service of performing cleanup upon container termination. In the default deployment, Redpill will execute an auto generated iptables rule removal script specified via the environment variable `OVPN_IPTB_DELETE`.

##### Version Information:

* **Container Release:** 1.1.0
* **OpenVPN:** 2.3.2-7ubuntu3.1
* **Keepalived:** 1:1.2.7-1ubuntu1


##### Services Include
* **[OpenVPN](#openvpn)** - Provides network access from the public network side to the Mesos-Network.
* **[Rsyslog](#rsyslog)** - The system logging daemon. Bundled to support logging for Keepalived.
* **[Keepalived](#keepalived)** - A well known and frequently used framework that provides load-balancing and fault tolerance via VRRP (Virtual Router Redundancy Protocol).
* **[Logrotate](#logrotate)** - A script and application that aid in pruning log files.
* **[Logstash-Forwarder](#logstash-forwarder)** - A lightweight log collector and shipper for use with [Logstash](https://www.elastic.co/products/logstash).
* **[Redpill](#redpill)** - A bash script and healthcheck for supervisord managed services. It is capable of running cleanup scripts that should be executed upon container termination.


---
---
### Index

* [Usage](#usage)
 * [Before you Build or Run](#read-this-before-you-attempt-to-run-or-build)
 * [Example Run Command](#example-run-command)
 * [Example Marathon App Definition](#example-marathon-app-definition)
* [Modification and Anatomy of the Project](#modification-and-anatomy-of-the-project)
* [Important Environment Variables](#important-environment-variables)
* [Service Configuration](#service-configuration)
 * [OpenVPN](#openvpn)
   * [Enabled Autoconfiguration](#enabled-autoconfiguration)
   * [Disabled Autoconfiguration](#disabled-autoconfiguration)
 * [Rsyslog](#rsyslog)
 * [Keepalived](#keepalived)
 * [Logrotate](#logrotate)
 * [Logstash-Forwarder](#logstash-forwarder)
 * [Redpill](#redpill)
* [Troubleshooting](#troubleshooting)

---
---

### Usage

#### READ THIS BEFORE YOU ATTEMPT TO RUN OR BUILD

There are two important things that **MUST** be done before attempting to deploy this container: 

1. Configure the host
2. Generate OpenVPN Certificates.

##### Host Preparation
The host(s) that this is intended to run on must have a few kernel settings configured to function correctly:
 * `net.ipv4.ip_nonlocal_bind=1` - For Keepalived to bind to an address that is not currently tied to a device.

 * `net.ipv4.ip_forward=1` - Allows the kernel to forward packets, needed by OpenVPN.

 Generally, these would be done to slaves that are dedicated to being the bridge between the Mesos-Network and Public-Network. It can sit alongside Bamboo/HAproxy containers on the same host without issue.


##### Certificate Preparation

`/etc/openvpn/certs/*`
All the certificate information needed to run OpenVPN should be stored in `/etc/openvpn/certs/`. These can be generated easily via EasyRSA (Ubuntu has a good guide here: [OpenVPN Public Key Infrastructure Setup](https://help.ubuntu.com/lts/serverguide/openvpn.html#openvpn-pki-setup)) or for convenience the `mrbobbytables/easyrsa` container can be pulled/built and used. It should include:
* `ca.crt` - The Certificate Authority certificate. This will only be needed to be used once to sign the server certificate and then distributed to the clients to verify the server.

* `dh2048.pem` - The server's Diffie-Hellman key file - can be generated with `openssl dhparam -out dh2048.pem 2048`. **Note:** This can take a significant amount of time depending on your system specs.

* `server.crt` - The signed server certificate for the OpenVPN server.

* `server.key` - The private key for the OpenVPN server.

Alternate filenames and paths can be used, they just need to be passed as [environment variables](#enabled-autoconfiguration) for the init script to handle.

---

##### Deploying in Production

For a production or development deployment with [Keepalived](#keepalived) enabled. There are close to a dozen important environment variables that should be set at a minimum.

**Configuration Parameters**

* `ENVIRONMENT` - when set to `production` or `development` it will enable all services including: `openvpn`, `rsyslog`, `keepalived`, `logrotate`, `logstash-forwarder`, and `redpill`.

* `OVPN_LOCAL` - This is the IP address that OpenVPN should listen on for incoming public connections.

* `OVPN_PUSH_###` - A quoted string containing a command to be pushed to the client. In general, there should always be at least one push command that passes the route to the client e.g. `OVPN_PUSH_1="push route 10.10.0.0 255.255.255.0"`. More than one can be supplied as long as the variable name ends in a number from 0-999. Other useful things to push are internally used DNS servers (e.g. Mesos-DNS). For a full list of options, please see the OpenVPN documentation and look up the push directive.

* `OVPN_NET_###` - A network and its associated interface on the host that should be routed through OpenVPN in the form of `<INTERFACE>:<SUBNET(CIDR NOTATION)>` e.g. `OVPN_NET_1=eth0:10.10.0.0/24`. It is used to auto generate the needed iptables rules. More than one can be supplied as long as the variable name ends in a number from 0-999.

* `KEEPALIVED_INTERFACE` - The host interface that keepalived will monitor and use for VRRP traffic. e.g. `eth0`

* `KEEPALIVED_VRRP_UNICAST_BIND` - The IP on the host that the keepalived daemon should bind to. **Note:** If not specified, it will be the first IP bound to the interface specified in `$KEEPALIVED_INTERFACE`

* `KEEPALIVED_VRRP_UNICAST_PEER` - The host IP of the peer in the VRRP group (the other host acting as an edge or proxy system).

* `KEEPALIVED_TRACK_INTERFACE_###` - An interface that’s state should be monitored (e.g. `eth0`). More than one can be supplied as long as the variable name ends in a number from 0-999. 

* `KEEPALIVED_VIRTUAL_IPADDRESS_###` - An instance of an address that will be monitored and failed over from one host to another. These should be a quoted string in the form of: `<IPADDRESS>/<MASK> brd <BROADCAST_IP> dev <DEVICE> scope <SCOPE> label <LABEL>` At a minimum the ip address, mask and device should be specified e.g. `KEEPALIVED_VIRTUAL_IPADDRESS_1="10.10.0.2/24 dev eth0"`. More than one can be supplied as long as the variable name ends in a number from 0-999. Note: Keepalived has a hard limit of 20 addresses that can be monitored. More can be failed over with the monitored addresses via `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###`. In general, this would be a floating IP on the private network side, and does not have to have any true intended purpose other than being a monitored IP.

* `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###` - An instance of an address that will be failed over with the monitored addresses supplied via KEEPALIVED_VIRTUAL_IPADDRESS_###. These should be a quoted string in the form of: `<IPADDRESS>/<MASK> brd <BROADCAST_IP> dev <DEVICE> scope <SCOPE> label <LABEL>` At a minimum the ip address, mask and device should be specified e.g. `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_1="172.16.1.20/24 dev eth1"`. More than one can be supplied as long as the variable name ends in a number from 0-999. This is ideal for any public facing IP addresses.

For further configuration parameters, please see either the [OpenVPN](#openvpn) or [Keepalived](#keepalived) Service sections.

---

### Example Run Command

**Master**
```bash
docker run -d --net=host --cap-add NET_ADMIN \
-e ENVIRONMENT=production \
-e PARENT_HOST=$(hostname) \
-e OVPN_LOCAL=172.16.1.20 \
-e OVPN_PUSH_1="route 10.10.0.0 255.255.255.0" \
-e OVPN_PUSH_2="dhcp-option DNS 10.10.0.111" \
-e OVPN_PUSH_3="dhcp-option DNS 10.10.0.112" \
-e OVPN_NET_1="eth0:10.10.0.0/24" \
-e KEEPALIVED_STATE=MASTER \
-e KEEPALIVED_INTERFACE=eth0 \
-e KEEPALIVED_VIRTUAL_ROUTER_ID=2 \
-e KEEPALIVED_VRRP_UNICAST_BIND=10.10.0.21 \
-e KEEPALIVED_VRRP_UNICAST_PEER=10.10.0.22 \
-e KEEPALIVED_TRACK_INTERFACE_1=eth0 \
-e KEEPALVED_TRACK_INTERFACE_2=eth1 \
-e KEEPALIVED_VIRTUAL_IPADDRESS_1="10.10.0.3 dev eth0" \
-e KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_1="172.16.1.20 dev eth1" \
openvpn
```

**Backup**
```bash
docker run -d --net=host --cap-add NET_ADMIN \
-e ENVIRONMENT=production \
-e PARENT_HOST=$(hostname) \
-e OVPN_LOCAL=172.16.1.20 \
-e OVPN_PUSH_1="route 10.10.0.0 255.255.255.0" \
-e OVPN_PUSH_2="dhcp-option DNS 10.10.0.111" \
-e OVPN_PUSH_3="dhcp-option DNS 10.10.0.112" \
-e OVPN_NET_1="eth0:10.10.0.0/24" \
-e KEEPALIVED_STATE=BACKUP \
-e KEEPALIVED_INTERFACE=eth0 \
-e KEEPALIVED_VIRTUAL_ROUTER_ID=2 \
-e KEEPALIVED_VRRP_UNICAST_BIND=10.10.0.22 \
-e KEEPALIVED_VRRP_UNICAST_PEER=10.10.0.21 \
-e KEEPALIVED_TRACK_INTERFACE_1=eth0 \
-e KEEPALVED_TRACK_INTERFACE_2=eth1 \
-e KEEPALIVED_VIRTUAL_IPADDRESS_1="10.10.0.3 dev eth0" \
-e KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_1="172.16.1.20 dev eth1" \
openvpn
```

---

### Example Marathon App Definition

**Master**
```json
{
    "id": "/ovpn/master",
    "instances": 1,
    "cpus": 1,
    "mem": 512,
    "constraints": [
        [
            "hostname",
            "CLUSTER",
            "10.10.0.21"
        ]
    ],
    "container": {
        "type": "DOCKER",
        "docker": {
            "image": "registry.address/mesos/ovpn",
            "network": "HOST",
            "parameters": [
                {
                    "key": "cap-add",
                    "value": "NET_ADMIN"
                }
            ]
        }
    },
    "env": {
        "ENVIRONMENT": "production",
        "APP_NAME": "ovpn",
        "PARENT_HOST": "mesos-proxy-01",
        "OVPN_LOCAL": "172.16.1.20",
        "OVPN_PUSH_1": "route 10.10.0.0 255.255.255.0",
        "OVPN_PUSH_2": "dhcp-option DNS 10.10.0.111",
        "OVPN_PUSH_3": "dhcp-option DNS 10.10.0.112",
        "OVPN_NET_1": "eth0:10.10.0.0/24",
        "KEEPALIVED_STATE": "MASTER",
        "KEEPALIVED_INTERFACE": "eth0",
        "KEEPALIVED_VIRTUAL_ROUTER_ID": "2",
        "KEEPALIVED_VRRP_UNICAST_BIND": "10.10.0.21",
        "KEEPALIVED_VRRP_UNICAST_PEER": "10.10.0.22",
        "KEEPALIVED_TRACK_INTERFACE_1": "eth0",
        "KEEPALIVED_TRACK_INTERFACE_2": "eth1",
        "KEEPALIVED_VIRTUAL_IPADDRESS_1": "10.10.0.3/24 dev eth0",
        "KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_1": "172.16.1.20/24 dev eth1"
    },
    "uris": [
      "file:///docker.tar.gz"
    ]
}
```

**Backup**
```json
{
    "id": "/ovpn/backup",
    "instances": 1,
    "cpus": 1,
    "mem": 512,
    "constraints": [
        [
            "hostname",
            "CLUSTER",
            "10.10.0.22"
        ]
    ],
    "container": {
        "type": "DOCKER",
        "docker": {
            "image": "registry.address/mesos/ovpn",
            "network": "HOST",
            "parameters": [
                {
                    "key": "cap-add",
                    "value": "NET_ADMIN"
                }
            ]
        }
    },
    "env": {
        "ENVIRONMENT": "production",
        "APP_NAME": "ovpn",
        "PARENT_HOST": "mesos-proxy-02",
        "OVPN_LOCAL": "172.16.1.20",
        "OVPN_PUSH_1": "route 10.10.0.0 255.255.255.0",
        "OVPN_PUSH_2": "dhcp-option DNS 10.10.0.111",
        "OVPN_PUSH_3": "dhcp-option DNS 10.10.0.112",
        "OVPN_NET_1": "eth0:10.10.0.0/24",
        "KEEPALIVED_STATE": "BACKUP",
        "KEEPALIVED_INTERFACE": "eth0",
        "KEEPALIVED_VIRTUAL_ROUTER_ID": "2",
        "KEEPALIVED_VRRP_UNICAST_BIND": "10.10.0.22",
        "KEEPALIVED_VRRP_UNICAST_PEER": "10.10.0.21",
        "KEEPALIVED_TRACK_INTERFACE_1": "eth0",
        "KEEPALIVED_TRACK_INTERFACE_2": "eth1",
        "KEEPALIVED_VIRTUAL_IPADDRESS_1": "10.10.0.3/24 dev eth0",
        "KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_1": "172.16.1.20/24 dev eth1"
    },
    "uris": [
      "file:///docker.tar.gz"
    ]
}
```


* **Note:** The example assumes a v1.6+ version of docker or a v2 version of the docker registry. For information on using an older version or connecting to a v1 registry, please see the [private registry](https://mesosphere.github.io/marathon/docs/native-docker-private-registry.html) section of the Marathon documentation.

---
---

### Modification and Anatomy of the Project

**File Structure**
The directory `skel` in the project root maps to the root of the file system once the container is built. Files and folders placed there will map to their corresponding location within the container.

**Init**
The init script (`./init.sh`) found at the root of the directory is the entry process for the container. It's role is to simply set specific environment variables and modify any subsequently required configuration files.

**OpenVPN**
The OpenVPN configuration is generally automatically created; however the certs and alternate configs can be placed in `/etc/openvpn/`.

**Supervisord**
All supervisord configs can be found in `/etc/supervisor/conf.d/`. Services by default will redirect their stdout to `/dev/fd/1` and stderr to `/dev/fd/2` allowing for service's console output to be displayed. Most applications can log to both stdout and their respectively specified log file.

In some cases (such as with zookeeper), it is possible to specify different logging levels and formats for each location.

**Logstash-Forwarder**
The Logstash-Forwarder binary and default configuration file can be found in `/skel/opt/logstash-forwarder`. It is ideal to bake the Logstash Server certificate into the base container at this location. If the certificate is called `logstash-forwarder.crt`, the default supplied Logstash-Forwarder config should not need to be modified, and the server setting may be passed through the `SERVICE_LOGSTASH_FORWARDER_ADDRESS` environment variable.

In practice, the supplied Logstash-Forwarder config should be used as an example to produce one tailored to each deployment.

---
---

### Important Environment Variables

#### Defaults

| **Variable**                      | **Default**                              |
|-----------------------------------|------------------------------------------|
| `ENVIRONMENT_INIT`                |                                          |
| `APP_NAME`                        | `openvpn`                                |
| `ENVIRONMENT`                     | `local`                                  |
| `PARENT_HOST`                     | `unknown`                                |
| `OVPN_AUTOCONF`                   | `enabled`                                |
| `OVPN_CONF`                       | `/etc/openvpn/ovpn.conf`                 |
| `OVPN_IPTB_CREATE`                | `/opt/scripts/create-iptb-rules.sh`      |
| `OVPN_IPTB_DELETE`                | `/opt/scripts/delete-iptb-rules.sh`      |
| `SERVICE_OVPN_CMD`                | `/usr/sbin/openvpn –config “$OVPN_CONF”` |
| `SERVICE_KEEPALIVED`              |                                          |
| `SERVICE_KEEPALIVED_CONF`         | `/etc/keepalived/keepalived.conf`        |
| `KEEPALIVED_AUTOCONF`             | `enabled`                                |
| `SERVICE_LOGROTATE`               |                                          |
| `SERVICE_LOGROTATE_INTERVAL`      | `3600` (set in script by default)        |
| `SERVICE_LOGSTASH_FORWARDER`      |                                          |
| `SERVICE_LOGSTASH_FORWARDER_CONF` | `/opt/logstash-forwarder/ovpn.conf`      |
| `SERVICE_REDPILL`                 |                                          |
| `SERVICE_REDPILL_MONITOR`         | `ovpn,keepalived`                        |
| `SERVICE_REDPILL_CLEANUP`         | `$IPTB_DELETE`                           |
| `SERVICE_RSYSLOG`                 | `enabled`                                |

#### Description

* `ENVIRONMENT_INIT` - If set, and the file path is valid. This will be sourced and executed before **ANYTHING** else. Useful if supplying an environment file or need to query a service such as consul to populate other variables.

* `APP_NAME` - A brief description of the container. If Logstash-Forwarder is enabled, this will populate the `app_name` field in the Logstash-Forwarder configuration file.

* `ENVIRONMENT` - Sets defaults for several other variables based on the current running environment. Please see the [environment](#environment) section for further information. If logstash-forwarder is enabled, this value will populate the `environment` field in the logstash-forwarder configuration file.

* `PARENT_HOST` - The name of the parent host. If Logstash-Forwarder is enabled, this will populate the `parent_host` field in the Logstash-Forwarder configuration file.

* `OVPN_AUTOCONF` - Enables or disables OpenVPN autoconfiguration. (**Options:** `enabled` or `disabled`) 

* `OVPN_CONF` - The path to the OpenVPN configuration file.

* `OVPN_IPTB_CREATE` - The path to the script containing the iptables rules to be executed before OpenVPN launches. This will be auto generated if `OVPN_AUTOCONF` is enabled.

* `OVPN_IPTB_DELETE` - The path to the script containing the iptables rules that should be executed upon container termination. For all intents and purposes, this should mirror the rules in the iptables creation file (`iptables -D` instead of `iptables -A`). If `OVPN_AUTOCONF` is enabled, this script will be autogenerated.

* `SERVICE_OVPN_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.

* `SERVICE_KEEPALIVED` - Enables or Disables the Keepalived service. Set automatically depending on the `ENVIRONMENT`. See the Environment section below.  (**Options:** `enabled` or `disabled`)

* `SERVICE_KEEPALIVED_CONF` - The path to keepalived config.

* `KEEPALIVED_AUTOCONF` - Enables or disables Keepalived autoconfiguration. (**Options:** `enabled` or `disabled`)

* `SERVICE_LOGROTATE` - Enables or disabled the Logrotate service. This will be set automatically depending on the environment. (**Options:** `enabled` or `disabled`)

* `SERVICE_LOGROTATE_INTERVAL` - The time in seconds between runs of logrotate or the logrotate script. The default (3600 or 1 hour) is set by default in the logrotate script automatically.

* `SERVICE_LOGSTASH_FORWARDER` - Enables or disables the Logstash-Forwarder service. Set automatically depending on the `ENVIRONMENT`. See the Environment section below.  (**Options:** `enabled` or `disabled`)

* `SERVICE_LOGSTASH_FORWARDER_CONF` - The path to the logstash-forwarder configuration.

* `SERVICE_REDPILL` - Enables or disables the Redpill service. Set automatically depending on the `ENVIRONMENT`. See the Environment section below.  (**Options:** `enabled` or `disabled`)

* `SERVICE_REDPILL_MONITOR` - The name of the supervisord service(s) that the Redpill service check script should monitor.

* `SERVICE_REDPILL_CLEANUP` - The path to the script that will be executed upon container termination. For OpenVPN this should clear any iptables rules from the host.

* `SERVICE_RSYSLOG` - Enables of disables the rsyslog service. This is `enabled` by default and should not be disabled unless manually mananging logging.

---


#### Environment

* `local` (default)

| **Variable**                 | **Default** |
|------------------------------|-------------|
| `SERVICE_KEEPALIVED`         | `disabled`  |
| `SERVICE_LOGROTATE`          | `enabled`   |
| `SERVICE_LOGSTASH_FORWARDER` | `disabled`  |
| `SERVICE_REDPILL`            | `enabled`   |


* `prod`|`production`|`dev`|`development`

| **Variable**                 | **Default** |
|------------------------------|-------------|
| `SERVICE_KEEPALIVED`         | `enabled`   |
| `SERVICE_LOGROTATE`          | `enabled`   |
| `SERVICE_LOGSTASH_FORWARDER` | `enabled`   |
| `SERVICE_REDPILL`            | `enabled`   |


* `debug`

| **Variable**                 | **Default**                                                 |
|------------------------------|-------------------------------------------------------------|
| `SERVICE_KEEPALIVED`         | `enabled`                                                   |
| `SERVICE_LOGROTATE`          | `disabled`                                                  |
| `SERVICE_LOGSTASH_FORWARDER` | `disabled`                                                  |
| `SERVICE_REDPILL`            | `enabled`                                                   |
| `SERVICE_KEEPALIVED_CMD`     | `/usr/sbin/keepalived -n -D -l -f $SERVICE_KEEPALIVED_CONF` |
| `OVPN_VERB`                  | `11`                                                        |

---
---

### Service Configuration

---

### OpenVPN


#### Enabled Autoconfiguration
If `OVPN_AUTOCONF` is set to enabled (default). The other variables will become available for use and overriding. The only variables that are truly required for baseline functionality are `OVPN_LOCAL`, `OVPN_PUSH_###`, and `OVPN_NET_###`.

##### Defaults
| **Variable**       | **Default**                         |
|--------------------|-------------------------------------|
| `OVPN_CONF`        | `/etc/openvpn/ovpn.conf`            |
| `OVPN_MODE`        | `server`                            |
| `OVPN_CA`          | `/etc/openvpn/certs/ca.crt`         |
| `OVPN_CERT`        | `/etc/openvpn/certs/server.crt`     |
| `OVPN_KEY`         | `/etc/openvpn/certs/server.key`     |
| `OVPN_DH`          | `/etc/openvpn/certs/dh2048.pem`     |
| `OVPN_CIPHER`      | `BF-CBC`                            |
| `OVPN_VERB`        | `1`                                 |
| `OVPN_LOCAL`       |                                     |
| `OVPN_PORT`        | `1194`                              |
| `OVPN_PROTO`       | `udp`                               |
| `OVPN_KEEPALIVE`   | `“10 120”`                          |
| `OVPN_SERVER`      | `“192.168.253.0 255.255.255.0”`     |
| `OVPN_PUSH_###`    |                                     |
| `OVPN_NET_###`     |                                     |
| `OVPN_IPTB_CREATE` | `/opt/scripts/create-iptb-rules.sh` |
| `OVPN_IPTB_DELETE` | `/opt/scripts/delete-iptb-rules.sh` |
| `IPTB_RULE_###`    |                                     |

##### Description
* `OVPN_CONF` - The path to the OpenVPN config.

* `OVPN_MODE` - OpenVPN 'major' mode.

* `OVPN_CA` - The path to the certificate authority root cert.

* `OVPN_CERT` - The path to the server's certificate (should be signed by the CA).

* `OVPN_KEY` - The path to the private key used to generate the server certificate.

* `OVPN_DH` - The path to the Diffie Hellman parameter file.

* `OVPN_CIPHER` - The cipher algorithm used by OpenVPN. To get a list of available cipher's execute the following command substituting the name of your container for the default `docker run --rm=true openvpn:latest openvpn --show-ciphers`.

* `OVPN_VERB` - The logging verbosity. Should be a value between 1-11.

* `OVPN_LOCAL` - The IP Address that OpenVPN should bind to. (**Required**)

* `OVPN_PORT` - The port the OpenVPN server will listen on.

* `OVPN_PROTO` - The protocol to use for OpenVPN (**Options:** `udp` or `tcp`)

* `OVPN_KEEPALIVE` - The keepalive settings used by the server.

* `OVPN_SERVER` - A quoted string that contains the network to be used as the VPN network expressed in the form of `"<SUBNET> <NETMASK>"`. e.g.,`OVPN_SERVER="192.168.253.0 255.255.255.0"`

* `OVPN_PUSH_###` - A quoted string containing a command to be pushed to the client. In general, there should always be at least one push command that passes the route to the client e.g. `OVPN_PUSH_1="push route 10.10.0.0 255.255.255.0"`. More than one can be supplied as long as the variable name ends in a number from 0-999. Other useful things to push are internally used DNS servers (e.g. Mesos-DNS). For a full list of options, please see the [OpenVPN documentation](https://community.openvpn.net/openvpn/wiki/Openvpn23ManPage) and look up the push directive.

* `OVPN_NET_###` - A network and its associated interface on the host that should be routed through OpenVPN in the form of `<INTERFACE>:<SUBNET(CIDR NOTATION)>` e.g. `OVPN_NET_1=eth0:10.10.0.0/24`. It is used to auto generate the needed iptables rules. More than one can be supplied as long as the variable name ends in a number from 0-999.

* `OVPN_IPTB_CREATE` - The path to the iptables rule creation script.

* `OVPN_IPTB_DELETE` - The path to the iptables rule deletion script.

* `IPTB_RULE_###` - An optional quoted string containing an iptables rule to be added to the two iptables scripts. They should **NOT** include either `iptables -A` or `iptables -D`, they will be added automatically. **Note:** They will be appended at the **END** of the iptables creation/deletion scripts.

**Note:** The following configuration block will automatically prepend any of the above configuration options in the final autogenerated config:
```
dev tun
comp-lzo
persist-key
persist-tun
user nobody
group nogroup
syslog openvpn
```


##### Example Autogenerated Server Config
```
dev tun
comp-lzo
persist-key
persist-tun
user nobody
group nogroup
syslog openvpn
mode server
ca /etc/openvpn/certs/ca.crt
cert /etc/openvpn/certs/server.crt
key /etc/openvpn/certs/server.key
dh /etc/openvpn/certs/dh2048.pem
cipher BF-CBC
verb 1
log-append /var/log/openvpn/ovpn.log
local 172.16.1.20
port 1194
proto udp
keepalive 10 120
server 192.168.253.0 255.255.255.0
push "route 10.10.0.0 255.255.255.0"
push "dhcp-option DNS 10.10.0.111"
push "dhcp-option DNS 10.10.0.112"
```

##### Example OpenVPN Client Configuration
```
float
port 1194
proto udp
dev tun
dev-type tun
remote 172.16.1.20
ping 10
persist-tun
persist-key
ca ca.crt
comp-lzo yes
client
verb 1
```

##### Example Auto Generated iptables Creation Script
```bash
#!/bin/bash
# Autocreated iptables creation script.
iptables -A INPUT -i eth1 -d 172.16.1.20 -p udp --dport 1194 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -o eth0 -s 192.168.253.0/24 -d 10.10.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun+ -s 10.10.0.0/24 -d 192.168.253.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A POSTROUTING -t nat -o eth0 -s 10.10.0.0/24 -d 192.168.253.0/24 -j MASQUERADE
iptables -A OUTPUT -o tun+ -j ACCEPT
```
##### Example Auto Generated iptables Deletion Script
```bash
#!/bin/bash
# Autocreated iptables deletion script.
iptables -D INPUT -i eth1 -d 172.16.1.20 -p udp --dport 1194 -m conntrack --ctstate NEW -j ACCEPT
iptables -D INPUT -i tun+ -j ACCEPT
iptables -D FORWARD -i tun+ -o eth0 -s 192.168.253.0/24 -d 10.10.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -i eth0 -o tun+ -s 10.10.0.0/24 -d 192.168.253.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -D POSTROUTING -t nat -o eth0 -s 10.10.0.0/24 -d 192.168.253.0/24 -j MASQUERADE
iptables -D OUTPUT -o tun+ -j ACCEPT
```

#### Disabled Autoconfiguration

If `OVPN_AUTOCONF` is disabled. you **must** provide your own configuration. With auto configuration disabled, the following variables are available for use:

##### Defaults

| **Variable**       | **Default**                         |
|--------------------|-------------------------------------|
| `OVPN_CONF`        | `/etc/openvpn/ovpn.conf`            |
| `OVPN_IPTB_CREATE` | `/opt/scripts/create-iptb-rules.sh` |
| `OVPN_IPTB_DELETE` | `/opt/scripts/delete-iptb-rules.sh` |
| `IPTB_RULE_###`    |                                     |


##### Description
* `OVPN_CONF` - The path to the OpenVPN config.

* `OVPN_IPTB_CREATE` - The path to the iptables rule creation script.

* `OVPN_IPTB_DELETE` - The path to the iptables rule deletion script.
 
* `IPTB_RULE_###` - An optional quoted string containing an iptables rule to be added to the two iptables scripts. They should **NOT** include either `iptables -A` or `iptables -D`, they will be added automatically. **Note:** They will be appended at the **END** of the iptables creation/deletion scripts.

---

### Rsyslog
Rsyslog is a high performance log processing daemon. Rsyslog is enabled at all times to provide logging for both Keepalived and OpenVPN. For any modifications to the config, it is best to edit the rsyslog configs directly (`/etc/rsyslog.conf` and `/etc/rsyslog.d/*`).

##### Defaults

| **Variable**                      | **Default**                                      |
|-----------------------------------|--------------------------------------------------|
| `SERVICE_RSYSLOG`                 | `enabled`                                        |
| `SERVICE_RSYSLOG_CONF`            | `/etc/rsyslog.conf`                              |
| `SERVICE_RSYSLOG_CMD`             | `/usr/sbin/rsyslogd -n -f $SERVICE_RSYSLOG_CONF` |

##### Description

* `SERVICE_RSYSLOG` - Enables or disables the rsyslog service. This will automatically be set depending on what other services are enabled. (**Options:** `enabled` or `disabled`)

* `SERVICE_RSYSLOG_CONF` - The path to the rsyslog configuration file.

* `SERVICE_RSYSLOG_CMD` -  The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.

---


### Keepalived

A battle-tested daemon built to handle load balancing and failover. If `KEEPALIVED_AUTOCONF` is enabled, it will auto generate a unicast based failover configuration with a minimal amount of user supplied information. For specific information on Keepalived, please see the man page on [keepalived.conf](http://linux.die.net/man/5/keepalived.conf) or the [Keepalived User Guide](http://www.keepalived.org/pdf/UserGuide.pdf).

#### Keepalived Service Variables

##### Defaults

| **Variable**              | **Default**                                           |
|---------------------------|-------------------------------------------------------|
| `SERVICE_KEEPALIVED`      |                                                       |
| `SERVICE_KEEPALIVED_CONF` | `/etc/keepalived/keepalived.conf`                     |
| `SERVICE_KEEPALIVED_CMD`  | `/usr/sbin/keepalived -n -f $SERVICE_KEEPALIVED_CONF` |


##### Description

* `SERVICE_KEEPALIVED` - Enables or disables the Keepalived service. Set automatically depending on the `ENVIRONMENT`. See the Environment section.  (**Options:** `enabled` or `disabled`)

* `SERVICE_KEEPALIVED_CONF` - The path to keepalived config.

* `SERVICE_KEEPALIVED_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.

---


#### Keepalived Auto Configuration Options

##### Defaults

| **Variable**                                | **Default**                        |
|---------------------------------------------|------------------------------------|
| `KEEPALIVED_AUTOCONF`                       | `enabled`                          |
| `KEEPALIVED_STATE`                          | `MASTER`                           |
| `KEEPALIVED_PRIORITY`                       | `200`                              |
| `KEEPALIVED_INTERFACE`                      | `eth0`                             |
| `KEEPALIVED_VIRTUAL_ROUTER_ID`              | `1`                                |
| `KEEPALIVED_ADVERT_INT`                     | `1`                                |
| `KEEPALIVED_AUTH_PASS`                      | `pwd$KEEPALIVED_VIRTUAL_ROUTER_ID` |
| `KEEPALIVED_VRRP_UNICAST_BIND`              |                                    |
| `KEEPALIVED_VRRP_UNICAST_PEER`              |                                    |
| `KEEPALIVED_TRACK_INTERFACE_###`            |                                    |
| `KEEPALIVED_VIRTUAL_IPADDRESS_###`          |                                    |
| `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###` |                                    |


##### Description

* `KEEPALIVED_AUTOCONF` - Enables or Disables Keepalived autoconfiguration. (**Options:** `enabled` or `disabled`)

* `KEEPALIVED_STATE` - Defines the server role as Master or Backup. (**Options:** `MASTER` or `BACKUP`).

* `KEEPALIVED_PRIORITY` - Election value, the server configured with the highest priority will become the Master.

* `KEEPALIVED_INTERFACE` - The host interface that keepalived will monitor and use for VRRP traffic.

* `KEEPALIVED_VIRTUAL_ROUTER_ID` - A unique number from 0 to 255 that should identify the VRRP group. Master and Backup should have the same value. Multiple instances of keepalived can be run on the same host, but each pair **MUST** have a unique virtual router id.

* `KEEPALIVED_ADVERT_INT` - The VRRP advertisement interval (in seconds).

* `KEEPALIVED_AUTH_PASS` - A shared password used to authenticate each node in a VRRP group (**Note:** If password is longer than 8 characters, only the first 8 characters are used).

* `KEEPALIVED_VRRP_UNICAST_BIND` - The IP on the host that the keepalived daemon should bind to. **Note:** If not specified, it will be the first IP bound to the interface specified in `$KEEPALIVED_INTERFACE`

* `KEEPALIVED_VRRP_UNICAST_PEER` - The IP of the peer in the VRRP group. (**Required**)

* `KEEPALIVED_TRACK_INTERFACE_###` - An interface that's state should be monitored (e.g. eth0). More than one can be supplied as long as the variable name ends in a number from 0-999.

* `KEEPALIVED_VIRTUAL_IPADDRESS_###` - An instance of an address that will be monitored and failed over from one host to another. These should be a quoted string in the form of: `<IPADDRESS>/<MASK> brd <BROADCAST_IP> dev <DEVICE> scope <SCOPE> label <LABEL>` At a minimum the ip address, mask and device should be specified e.g. `KEEPALIVED_VIRTUAL_IPADDRESS_1="10.10.0.2/24 dev eth0"`. More than one can be supplied as long as the variable name ends in a number from 0-999. **Note:** Keepalived has a hard limit of **20** addresses that can be monitored. More can be failed over with the monitored addresses via `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###`. (**Required**)

* `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_###` - An instance of an address that will be failed over with the monitored addresses supplied via `KEEPALIVED_VIRTUAL_IPADDRESS_###`.  These should be a quoted string in the form of: `<IPADDRESS>/<MASK> brd <BROADCAST_IP> dev <DEVICE> scope <SCOPE> label <LABEL>` At a minimum the ip address, mask and device should be specified e.g. `KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_1="172.16.1.20/24 dev eth1"`. More than one can be supplied as long as the variable name ends in a number from 0-999.

##### Example Autogenerated Keepalived Master Config
```
vrrp_instance MAIN {
  state MASTER
  interface eth0
  vrrp_unicast_bind 10.10.0.21
  vrrp_unicast_peer 10.10.0.22
  virtual_router_id 2
  priority 200
  advert_int 1
  authentication {
    auth_type PASS
    auth_pass pwd1
  }
  virtual_ipaddress {
    10.10.0.2/24 dev eth0
  }
  virtual_ipaddress_excluded {
    172.16.1.20/24 dev eth1
  }
  track_interface {
    eth0
    eth1
  }
}

```

##### Example Autogenerated Keepalived Backup Config
```
vrrp_instance MAIN {
  state BACKUP
  interface eth0
  vrrp_unicast_bind 10.10.0.22
  vrrp_unicast_peer 10.10.0.21
  virtual_router_id 2
  priority 100
  advert_int 1
  authentication {
    auth_type PASS
    auth_pass pwd1
  }
  virtual_ipaddress {
    10.10.0.2/24 dev eth0
  }
  virtual_ipaddress_excluded {
    172.16.1.20/24 dev eth1
  }
  track_interface {
    eth0
    eth1
  }
}

```

---


### Logrotate

The logrotate script is a small simple script that will either call and execute logrotate on a given interval; or execute a supplied script. This is useful for applications that do not perform their own log cleanup.

#### Logrotate Environment Variables

##### Defaults

| **Variable**                 | **Default**                           |
|------------------------------|---------------------------------------|
| `SERVICE_LOGROTATE`          |                                       |
| `SERVICE_LOGROTATE_INTERVAL` | `3600` (set in script)                |
| `SERVICE_LOGROTATE_CONFIG`   | `/etc/logrotate.conf` (set in script) |
| `SERVICE_LOGROTATE_SCRIPT`   |                                       |
| `SERVICE_LOGROTATE_FORCE`    |                                       |
| `SERVICE_LOGROTATE_VERBOSE`  |                                       |
| `SERVICE_LOGROTATE_DEBUG`    |                                       |
| `SERVICE_LOGROTATE_CMD`      | `/opt/script/logrotate.sh <flags>`    |

##### Description

* `SERVICE_LOGROTATE` - Enables or disables the Logrotate service. Set automatically depending on the `ENVIRONMENT`. See the Environment section.  (**Options:** `enabled` or `disabled`)

* `SERVICE_LOGROTATE_INTERVAL` - The time in seconds between run of either the logrotate command or the provided logrotate script. Default is set to `3600` or 1 hour in the script itself.

* `SERVICE_LOGROTATE_CONFIG` - The path to the logrotate config file. If neither config or script is provided, it will default to `/etc/logrotate.conf`.

* `SERVICE_LOGROTATE_SCRIPT` - A script that should be executed on the provided interval. Useful to do cleanup of logs for applications that already handle rotation, or if additional processing is required.

* `SERVICE_LOGROTATE_FORCE` - If present, passes the 'force' command to logrotate. Will be ignored if a script is provided.

* `SERVICE_LOGROTATE_VERBOSE` - If present, passes the 'verbose' command to logrotate. Will be ignored if a script is provided.

* `SERVICE_LOGROTATE_DEBUG` - If present, passed the 'debug' command to logrotate. Will be ignored if a script is provided.

* `SERVICE_LOGROTATE_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.


##### Logrotate Script Help Text
```
root@ec58ca7459cb:/opt/scripts# ./logrotate.sh --help
logrotate.sh - Small wrapper script for logrotate.
-i | --interval     The interval in seconds that logrotate should run.
-c | --config       Path to the logrotate config.
-s | --script       A script to be executed in place of logrotate.
-f | --force        Forces log rotation.
-v | --verbose      Display verbose output.
-d | --debug        Enable debugging, and implies verbose output. No state file changes.
-h | --help         This usage text.
```


---

### Logstash-Forwarder

Logstash-Forwarder is a lightweight application that collects and forwards logs to a logstash server endpoint for further processing. For more information see the [Logstash-Forwarder](https://github.com/elastic/logstash-forwarder) project.


#### Logstash-Forwarder Environment Variables

##### Defaults

| **Variable**                         | **Default**                                                                             |
|--------------------------------------|-----------------------------------------------------------------------------------------|
| `SERVICE_LOGSTASH_FORWARDER`         |                                                                                         |
| `SERVICE_LOGSTASH_FORWARDER_CONF`    | `/opt/logstash-forwarder/ovpn.conf`                                                      |
| `SERVICE_LOGSTASH_FORWARDER_ADDRESS` |                                                                                         |
| `SERVICE_LOGSTASH_FORWARDER_CERT`    |                                                                                         |
| `SERVICE_LOGSTASH_FORWARDER_CMD`     | `/opt/logstash-forwarder/logstash-forwarder -config=”$SERVICE_LOGSTASH_FORWARDER_CONF”` |


##### Description

* `SERVICE_LOGSTASH_FORWARDER` - Enables or disables the Logstash-Forwarder service. Set automatically depending on the `ENVIRONMENT`. See the Environment section.  (**Options:** `enabled` or `disabled`)

* `SERVICE_LOGSTASH_FORWARDER_CONF` - The path to the logstash-forwarder configuration.

* `SERVICE_LOGSTASH_FORWARDER_ADDRESS` - The address of the Logstash server.

* `SERVICE_LOGSTASH_FORWARDER_CERT` - The path to the Logstash-Forwarder server certificate.

* `SERVICE_LOGSTASH_FORWARDER_CMD` - The command that is passed to supervisor. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.

---

### Redpill

Redpill is a small script that performs status checks on services managed through supervisor. In the event of a failed service (FATAL) Redpill optionally runs a cleanup script and then terminates the parent supervisor process.


#### Redpill Environment Variables

##### Defaults

| **Variable**               | **Default**         |
|----------------------------|---------------------|
| `SERVICE_REDPILL`          |                     |
| `SERVICE_REDPILL_MONITOR`  | `ovpn,keepalived`   |
| `SERVICE_REDPILL_INTERVAL` |                     |
| `SERVICE_REDPILL_CLEANUP`  | `$IPTB_DELETE`      |
| `SERVICE_REDPILL_CMD`      |                     |


##### Description

* `SERVICE_REDPILL` - Enables or disables the Redpill service. Set automatically depending on the `ENVIRONMENT`. See the Environment section.  (**Options:** `enabled` or `disabled`)

* `SERVICE_REDPILL_MONITOR` - The name of the supervisord service(s) that the Redpill service check script should monitor.

* `SERVICE_REDPILL_INTERVAL` - The interval in which Redpill polls supervisor for status checks. (Default for the script is 30 seconds)

* `SERVICE_REDPILL_CLEANUP` - The path to the script that will be executed upon container termination. For OpenVPN this should clear any iptables rules from the host.

* `SERVICE_REDPILL_CMD` - The command that is passed to supervisor. It is dynamically built from the other redpill variables. If overriding, must be an escaped python string expression. Please see the [Supervisord Command Documentation](http://supervisord.org/configuration.html#program-x-section-settings) for further information.


##### Redpill Script Help Text
```
root@c90c98ae31e1:/# /opt/scripts/redpill.sh --help
Redpill - Supervisor status monitor. Terminates the supervisor process if any specified service enters a FATAL state.

-c | --cleanup    Optional path to cleanup script that should be executed upon exit.
-h | --help       This help text.
-i | --interval   Optional interval at which the service check is performed in seconds. (Default: 30)
-s | --service    A comma delimited list of the supervisor service names that should be monitored.
```

---
---

### Troubleshooting

##### General Issues
In the event of an issue, the `ENVIRONMENT` variable can be set to `debug` to stop the container from shipping logs and terminating in the event of a fatal error (**Note:** This will also prevent the iptables cleanup script from executing automatically). This will also automatically set the log verbosity to it's max value of `11`. In many cases this may be too high and suggest overriding it, starting it with something smaller. Below is a snippet on logging levels from the [OpenVPN Documentation](https://community.openvpn.net/openvpn/wiki/Openvpn23ManPage).
```
0 -- No output except fatal errors.
1 to 4 -- Normal usage range.
5 -- Output R and W characters to the console for each packet read and write, uppercase is used for TCP/UDP packets and lowercase is used for TUN/TAP packets.
6 to 11 -- Debug info range (see errlevel.h for additional information on debug levels).
```



