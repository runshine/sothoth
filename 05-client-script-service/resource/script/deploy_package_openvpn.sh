#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh openvpn

[ -d "${ROOT_DIR}/usr/etc/openvpn" ] || mkdir -p "${ROOT_DIR}/usr/etc/openvpn"

cat <<EOF > "${ROOT_DIR}/usr/etc/openvpn/ca.crt"
-----BEGIN CERTIFICATE-----
MIID+TCCAuGgAwIBAgIUM+Zdm0FYUQP3dFXgwDaAygk25QwwDQYJKoZIhvcNAQEL
BQAwgYsxCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJHRDERMA8GA1UEBwwIU2hlbnpo
ZW4xDTALBgNVBAoMBElDU0wxDTALBgNVBAsMBElDU0wxGDAWBgNVBAMMD2ljc2wu
aHVhd2VpLmNvbTEkMCIGCSqGSIb3DQEJARYVYWRtaW5AaWNzbC5odWF3ZWkuY29t
MB4XDTI1MDcyMzIzNTA0NloXDTM1MDcyMTIzNTA0NlowgYsxCzAJBgNVBAYTAkNO
MQswCQYDVQQIDAJHRDERMA8GA1UEBwwIU2hlbnpoZW4xDTALBgNVBAoMBElDU0wx
DTALBgNVBAsMBElDU0wxGDAWBgNVBAMMD2ljc2wuaHVhd2VpLmNvbTEkMCIGCSqG
SIb3DQEJARYVYWRtaW5AaWNzbC5odWF3ZWkuY29tMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAskXZyfuJ2m8qy/4BGbv7YHgtVD5hG2Pm4ru2INX8LY0O
Ld2bIEkM/L63cfkg90J8C+K62omn2S/r8ndVSWNYp0Yprd52OkfKOOqtolIaVgbj
y2hwD9KCiI/glY4ni0HZOksFRnUIFCX4JPllprfr1cctYA4Gn+RAZ8PwPhvDf9YT
qwiRMxpHIYFiXsrDXudJ+1Wp8cDLoBRA/gF9lPRST3OBDd0Wtlb4ci61lvrljZVM
NeVxrJ8Htj+9uM5unZ7Y2h/EkJO/PMsZxKVVArXePe0zz/wM9rZ+MuR4Yht2kW2h
MVaFZ5vzHJcuONKQlb+5/DssTmJXRSAKoWEMI0EfdQIDAQABo1MwUTAdBgNVHQ4E
FgQUH0cDZVb/dCVLTM02ZjRgg/15pv8wHwYDVR0jBBgwFoAUH0cDZVb/dCVLTM02
ZjRgg/15pv8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAGi7K
p6WArDlhzPFl9/waz/NJ4ahZ+k6l5s67wsUaRqsmsfATgbM+oTofqIIGTjWa20iz
BJQ2OC8niy0WYnehWHLDAVCQx6fBWok//IzKWXG4PKj9AaCaZnCYUFHlH2VEHUDI
jYMIFNofWjmDseNgcbqNYo1acR47+DV0Yxw8G58WIsg6AVwNYEJzoQbxzdgsmOsi
/4hSJ/+hwQKoerfyxrxr6XXZkaQ8swdaxI8NmKQsutn7Xeg4lyf1totqcn+kOZp6
8Pf0jAJPjnKCznh053ACmiqSby4lRw4pfUiD09pc3tau/a4X9HkCX0ZJZyK/uI9H
u77i56rLn6gzj/DlHg==
-----END CERTIFICATE-----
EOF

cat <<EOF > "${ROOT_DIR}/usr/etc/openvpn/auth.txt"
$NODE_ID
pass
EOF

cat <<EOF > "${ROOT_DIR}/usr/etc/openvpn/client.ovpn"
client
dev tap-sothoth
proto udp
;remote $UPSTREAM_SERVER 11194
remote 127.0.0.1 11194
tls-client
cipher none
auth none
ca ${ROOT_DIR}/usr/etc/openvpn/ca.crt
auth-user-pass ${ROOT_DIR}/usr/etc/openvpn/auth.txt
nobind
persist-key
persist-tun
log ${ROOT_DIR}/var/log/openvpn.log
status ${ROOT_DIR}/var/run/openvpn-status.log
verb 3
keepalive 10 60
reneg-sec 0
remote-random
EOF


cat  <<EOF > ${ROOT_DIR}/service_config/01_openvpn_service.json
{
  "name": "openvpn",
  "description": "openvpn service",
  "start_cmd": "${ROOT_DIR}/usr/bin/openvpn --config \"${ROOT_DIR}/usr/etc/openvpn/client.ovpn\" --writepid \"$ROOT_DIR/var/run/openvpn.pid\" --iproute  \"$ROOT_DIR/usr/bin/ip\" ",
  "pid_file": "${ROOT_DIR}/var/run/openvpn.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_openvpn_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_openvpn_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "self",
  "check_interval": 10,
  "max_failures": 2,
  "depends_on": []
}
EOF

#if [ ! -c "/dev/net/tun" ];then
#  if [ ! -d "/dev/net" ];then
#    mkdir -p "/dev/net"
#    chmod 777 '/dev/net'
#  fi
#  mknod /dev/net/tun c 10 200
#  chmod 0666 /dev/net/tun
#fi

#"${OPENVPN_ROOT_DIR}/../utils/openvpn" --config "${OPENVPN_ROOT_DIR}/conf/client.ovpn" --writepid "$OPENVPN_ROOT_DIR/run/client.pid" --iproute  "$OPENVPN_ROOT_DIR/../utils/ip" &

