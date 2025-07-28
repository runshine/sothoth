#!/bin/sh

OPENSSH_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../openssh"
ARCH="$(uname -m)"
OS="linux"
WORKSPACE="$1"
UPSTREAM="$2"
UPSTREAM_SERVER="$(echo $2 | awk -F':' '{print $1}')"
UPSTREAM_PORT="$(echo $2 | awk -F':' '{print $2}')"
cd "$(cd "$(dirname $0)";pwd)"
if [ ! -d "${OPENSSH_ROOT_DIR}" ];then
  mkdir -p "${OPENSSH_ROOT_DIR}"
fi
. "${OPENSSH_ROOT_DIR}/../script/common.sh"

pre_build_dirs="$OPENSSH_ROOT_DIR $OPENSSH_ROOT_DIR/run $OPENSSH_ROOT_DIR/log $OPENSSH_ROOT_DIR/var/empty"
prepare_dir "$pre_build_dirs"

if [ ! -f "${OPENSSH_ROOT_DIR}/bin/ssh" ] && [ ! -f "${OPENSSH_ROOT_DIR}/sbin/sshd" ];then
  download "$UPSTREAM/package/openssh/$OS/$ARCH" "${OPENSSH_ROOT_DIR}/openssh.tar.gz"
  tar -zxvf "${OPENSSH_ROOT_DIR}/openssh.tar.gz" -C "${OPENSSH_ROOT_DIR}/../" 1>/dev/null
  if [ $? -eq 0 ];then
    logger "openssh decompress process success!"
    sed -i "s#/opt/openssh#${OPENSSH_ROOT_DIR}#g" "${OPENSSH_ROOT_DIR}/etc/sshd_config"
  else
    logger "openssh decompress process failed!"
  fi
fi

if [ ! -f "${OPENSSH_ROOT_DIR}/etc/authorized_keys" ];then
  logger "download ssh pubkey from server"
  download "$UPSTREAM/download/conf/openssh/id_rsa.pub" "id_rsa.pub"
  if [ -f "id_rsa.pub" ];then
    cat id_rsa.pub > "${OPENSSH_ROOT_DIR}/etc/authorized_keys"
    rm "id_rsa.pub"
  fi
fi

chown root:root "$OPENSSH_ROOT_DIR/var/empty"
chmod 711 -R "$OPENSSH_ROOT_DIR/var/empty"
if [ ! -L "/opt/openssh" ];then
  ln -s "$OPENSSH_ROOT_DIR" "/opt/openssh"
fi

if [ ! -f "${OPENSSH_ROOT_DIR}/etc/ssh_host_rsa_key" ]  || [ ! -f "${OPENSSH_ROOT_DIR}/etc/ssh_host_ecdsa_key" ] || [ ! -f "${OPENSSH_ROOT_DIR}/etc/ssh_host_ed25519_key" ] ;then
  chmod +x "${OPENSSH_ROOT_DIR}/bin/ssh-keygen"
  # 生成 RSA 密钥
  "${OPENSSH_ROOT_DIR}/bin/ssh-keygen" -t rsa -f "${OPENSSH_ROOT_DIR}/etc/ssh_host_rsa_key" -N "" -C ""
  # 生成 ECDSA 密钥
  "${OPENSSH_ROOT_DIR}/bin/ssh-keygen" -t ecdsa -f "${OPENSSH_ROOT_DIR}/etc/ssh_host_ecdsa_key" -N "" -C ""
  # 生成 ED25519 密钥
  "${OPENSSH_ROOT_DIR}/bin/ssh-keygen" -t ed25519 -f "${OPENSSH_ROOT_DIR}/etc/ssh_host_ed25519_key" -N "" -C ""
fi

if ! is_pid_file_running "${OPENSSH_ROOT_DIR}/run/sshd.pid";then
  logger "start openssh server: \"${OPENSSH_ROOT_DIR}/sbin/sshd\" -f \"${OPENSSH_ROOT_DIR}/etc/sshd_config\" -E \"${OPENSSH_ROOT_DIR}/log/sshd.log\""
  "${OPENSSH_ROOT_DIR}/sbin/sshd" -f "${OPENSSH_ROOT_DIR}/etc/sshd_config" -E "${OPENSSH_ROOT_DIR}/log/sshd.log"
  #NACOS_ROOT_DIR="${NACOS_ROOT_DIR}" UPSTREAM_SERVER="${UPSTREAM_SERVER}" "${NACOS_ROOT_DIR}/../python/bin/python" "${NACOS_ROOT_DIR}/script/nacos_client.py" &
  #echo "$!" > "${OPENSSH_ROOT_DIR}/run/sshd.pid"
else
  logger "openssh server already run, ignore re-run, pid: $(cat ${OPENSSH_ROOT_DIR}/run/sshd.pid)"
fi

