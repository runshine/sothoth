#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

deploy_package.sh sothothv1_agent

mkdir -p "${ROOT_DIR}/usr/sothoth"
cat <<START_SCRIPT > ${ROOT_DIR}/usr/sothoth/start.sh
#!/bin/sh

set -e

ROOT_DIR="${ROOT_DIR}"
PROJECT_ID="${PROJECT_ID}"
NODE_ID="${NODE_ID}"

MAX_RETRIES=600
RETRY_INTERVAL=2

echo "Starting IP resolution for nginx-server.sothoth.svc.cluster.local..."

retry_count=0
while [ \$retry_count -lt \$MAX_RETRIES ]; do
  SERVER_IP=\$( \${ROOT_DIR}/usr/bin/busybox nslookup nginx-server.sothoth.svc.cluster.local ${DNS_SERVER} 2>/dev/null | grep -E '^Address: ' | grep -v '#' | awk '{print \$2}' | head -n1 )
  
  if [ -n "\$SERVER_IP" ]; then
    echo "IP resolved successfully: \${SERVER_IP}"
    echo "Starting sothothv1_agent..."
    exec \${ROOT_DIR}/usr/bin/sothothv1_agent -server=http://\${SERVER_IP}:80 -projectId=\${PROJECT_ID} -nodeId=\${NODE_ID} -gaiasecDir=\${ROOT_DIR}/usr/sothoth -autohook
  fi
  
  retry_count=\$((retry_count + 1))
  echo "IP resolution attempt \$retry_count failed, retrying in \${RETRY_INTERVAL}s..."
  sleep \$RETRY_INTERVAL
done

echo "Failed to resolve IP after \${MAX_RETRIES} attempts"
exit 1
START_SCRIPT

chmod +x ${ROOT_DIR}/usr/sothoth/start.sh

cat  <<EOF > ${ROOT_DIR}/service_config/99_sothothv1_service.json
{
  "name": "sothoth",
  "description": "sothoth v1 service",
  "start_cmd": "${ROOT_DIR}/usr/sothoth/start.sh",
  "pid_file": "${ROOT_DIR}/usr/sothoth/nodeagent.pid",
  "stdout_log": "${ROOT_DIR}/var/log/monitor_sothothv1_stdout.log",
  "stderr_log": "${ROOT_DIR}/var/log/monitor_sothothv1_stderr.log",
  "work_dir": "${ROOT_DIR}/usr/sothoth",
  "monitor_mode": "monitor",
  "check_interval": 30,
  "max_failures": 2,
  "depends_on": [],
  "shell": false
}
EOF
