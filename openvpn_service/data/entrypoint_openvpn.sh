#!/bin/bash
echo "$(date): Running openvpn new entrypoint"
bridge_name="br-openvpn"
if [ "x${NET_START}" != "x" ] && [ "x${NET_END}" != "x" ] ; then
  if [ "x${MASTER}" == "xtrue" ];then
    if [ "x$(brctl show ${bridge_name} 2>/dev/null)" == "x" ];then
      echo "$(date): we are master server, should setup bridge first: ${bridge_name}"
      ip addr del ${MASTER_IP}/16 dev eth0
      brctl addbr ${bridge_name}
      brctl addif ${bridge_name} eth0
      ifconfig ${bridge_name} up
      ip addr add ${MASTER_IP}/16 dev ${bridge_name}
      ip route add default via ${MASTER_GW}
      ip addr add "$(echo ${MASTER_IP} | cut -d '.' -f 1-2).0.3" dev eth0
    else
      echo "$(date): bridge ${bridge_name} already setup, ignore re-setup it"
    fi
  else
    while [ "x$(brctl show ${bridge_name} 2>/dev/null)" == "x" ]
    do
      echo "$(date): start wait bridge ${bridge_name} avaiable, sleeping 2 second"
      sleep 2
    done
    echo "bridge ${bridge_name} is avaiable"
  fi
  echo "$(date): start generate config, ip range is: ${NET_START} --> ${NET_END}"

if [ ! -d "/tmp/opepnvpn" ];then
  mkdir -p "/tmp/openvpn"
fi

cat << EOF > /server.ovpn
port ${PORT}
dev tap
proto udp
server-bridge ${MASTER_IP} 255.255.0.0 ${NET_START} ${NET_END}
tls-server
verify-client-cert none
auth none
cipher none
;data-ciphers none
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
auth-user-pass-verify "/bin/true" via-env  # 始终返回验证成功的虚拟脚本
username-as-common-name
topology subnet
persist-key
persist-tun
keepalive 10 60
status /tmp/openvpn/openvpn-${PORT}-status.log
verb 3
client-to-client
script-security 2
up "/data/up.sh"
reneg-sec 0
EOF

else
  echo "env NET_START or env NET_END not start, unable start"
  exit 255
fi

echo "$(date): Running old entrypoint: /usr/sbin/openvpn --config /server.ovpn"
# Run OpennConnect Server
exec /usr/sbin/openvpn --config /server.ovpn