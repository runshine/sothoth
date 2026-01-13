#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh openssh

[ -d "${ROOT_DIR}/var/empty" ] || mkdir -p  "${ROOT_DIR}/var/empty"
[ -d "${ROOT_DIR}/usr/etc/ssh" ] || mkdir -p  "${ROOT_DIR}/usr/etc/ssh"
chown root:root "${ROOT_DIR}/var/empty"
chmod 711 -R "$ROOT_DIR/var/empty"


cat << EOF > ${ROOT_DIR}/usr/etc/ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdoj/xZM0I8nisbAR8ID4chJv2eyRNhjsnT0YVVXXkjigc08aOk57iU+xUQzRgKv1RV/dmsPoWdXPiqvRx69KGU0mBwrfkInLtvPalNlT4vOQRViQe0xuAehwGLUwR1uGiyu8hD82zfrvB8J2/c867CkZo5lz0dhq533KO/SxBBLh99fpVVsAiQ/bbiJO/XasIJebG0wkKPbRxgNWmL4KhIuujl9SmROvW32T1CwlEdw04SFQifjD/1cHoXPvStui5ZV9/sFbDnkTw7k91taA0ykTjhugv1zn4OhkH2DVFtlCOanHMDcfxKVwGlCoul40pBFn300SWpQedVJTbuKa+4sFO0PV8x1l1t/Ho2UH09fxIpObg05av7DIIW1O0qgOazbMHg4XY+Zt2RirfIQ6fRrZylN447PuA1VdFstdMy5i4FNmk1k541IDdQum2KB2lTZG72zoRCgE52m/JzqlofRKv/0d5FHLg7hDJaR9S96rnkEenaeMh3kYzl0FRxX8= root@runshine-Ubuntu
EOF
chmod 600 ${ROOT_DIR}/usr/etc/ssh/id_rsa.pub


#if [ ! -L "/opt/openssh" ];then
#  ln -s "${ROOT_DIR}/usr" "/opt/openssh"
#else
#  rm "/opt/openssh" -f
#  ln -s "${ROOT_DIR}/usr" "/opt/openssh"
#fi

if [ ! -f "${ROOT_DIR}/usr/etc/ssh/ssh_host_rsa_key" ]  || [ ! -f "${ROOT_DIR}/usr/etc/ssh/ssh_host_ecdsa_key" ] || [ ! -f "${ROOT_DIR}/usr/etc/ssh/ssh_host_ed25519_key" ] ;then
  chmod +x "${ROOT_DIR}/usr/bin/ssh-keygen"
  # 生成 RSA 密钥
  "${ROOT_DIR}/usr/bin/ssh-keygen" -t rsa -f "${ROOT_DIR}/usr/etc/ssh/ssh_host_rsa_key" -N "" -C ""
  # 生成 ECDSA 密钥
  "${ROOT_DIR}/usr/bin/ssh-keygen" -t ecdsa -f "${ROOT_DIR}/usr/etc/ssh/ssh_host_ecdsa_key" -N "" -C ""
  # 生成 ED25519 密钥
  "${ROOT_DIR}/usr/bin/ssh-keygen" -t ed25519 -f "${ROOT_DIR}/usr/etc/ssh/ssh_host_ed25519_key" -N "" -C ""
fi


cat << EOF > "${ROOT_DIR}/usr/etc/ssh/sshd_config"
#       $OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/bin:/usr/bin:/sbin:/usr/sbin:/opt/openssh/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Port 11192
#AddressFamily any
ListenAddress 0.0.0.0
#ListenAddress ::

HostKey ${ROOT_DIR}/usr/etc/ssh/ssh_host_rsa_key
HostKey ${ROOT_DIR}/usr/etc/ssh/ssh_host_ecdsa_key
HostKey ${ROOT_DIR}/usr/etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile      ${ROOT_DIR}/usr/etc/ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /opt/openssh/etc/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
PermitEmptyPasswords no

# Change to no to disable s/key passwords
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin prohibit-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
#UsePAM no

AllowAgentForwarding yes
AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
PidFile ${ROOT_DIR}/var/run/sshd.pid
#MaxStartups 10:30:100
PermitTunnel yes
#ChrootDirectory  none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem       sftp    ${ROOT_DIR}/usr/libexec/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server

EOF


cat  <<EOF > ${ROOT_DIR}/service_config/03_openssh_service.json
{
  "name": "openssh",
  "description": "openssh service",
  "start_cmd": "${ROOT_DIR}/usr/sbin/sshd  -f \"${ROOT_DIR}/usr/etc/ssh/sshd_config\" -E \"${ROOT_DIR}/var/log/sshd.log\"",
  "pid_file": "${ROOT_DIR}/var/run/sshd.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_sshd_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_sshd_stderr.log",
  "work_dir": "${ROOT_DIR}",
  "monitor_mode": "self",
  "check_interval": 10,
  "max_failures": 2,
  "depends_on": []
}
EOF

