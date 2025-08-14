#!/bin/sh

cd "$(dirname $0)"

pid="$1"
if [ "x${pid}" = "x" ];then
  echo "You must input pid"
  exit 255
fi

if [ "x${SOTHOTH_DIR}" = "x" ] || [ ! -d "/host/${SOTHOTH_DIR}" ] || [ ! -f "/host/${SOTHOTH_DIR}/sothoth.conf" ];then
  echo "Env SOTHOTH_DIR must set and exist, and must ok, current SOTHOTH_DIR --> ${SOTHOTH_DIR}"
  sleep 100
  exit 255
fi

if [ ! -d "/host/${SOTHOTH_DIR}/share/" ];then
  mkdir -p "/host/${SOTHOTH_DIR}/share/"
fi

chmod 755  "/host/${SOTHOTH_DIR}/share/"

if [ ! -f "${SOTHOTH_DIR}/share/libreboot_helper.so" ];then
  cp /libreboot_helper.so         "/host/${SOTHOTH_DIR}/share/libreboot_helper.so"
  cp /attach_helper.jar           "/host/${SOTHOTH_DIR}/share/attach_helper.jar"
  cp /opentelemetry-javaagent.jar "/host/${SOTHOTH_DIR}/share/opentelemetry-javaagent.jar"
  cp /addmount                   "/host/${SOTHOTH_DIR}/share/addmount"
  chmod 755 "/host/${SOTHOTH_DIR}/share/libreboot_helper.so"
  chmod 755 "/host/${SOTHOTH_DIR}/share/attach_helper.jar"
  chmod 755 "/host/${SOTHOTH_DIR}/share/opentelemetry-javaagent.jar"
  chmod 755 "/host/${SOTHOTH_DIR}/share/addmount"
else
  echo "file already exist, ignore copy"
fi

nspid="$(cat "/proc/${pid}/status" | grep NSpid | awk '{print $2}')"
if [ "x${nspid}" = "x" ];then
  echo "Pid error, not exist: ${pid}"
  exit 255
fi

host_pid_ns=$(readlink /proc/1/ns/pid)
process_pid_ns=$(readlink /proc/$pid/ns/pid)

add_mount_for_container(){
  while [ "1" = "1" ];
  do
   if [ "x$(nsenter -t $pid -m ls -ll "${SOTHOTH_DIR}" 2>/dev/null)" = "x" ];then
      nsenter -t $pid -m mkdir -p "${SOTHOTH_DIR}"
    fi
    if [ "x$(nsenter -t $pid -m ls -ll "${SOTHOTH_DIR}/sothoth.conf" 2>/dev/null)" = "x" ];then
      echo "not mount, try to add new mount"
      /addmount 1 "${SOTHOTH_DIR}" "$pid" "${SOTHOTH_DIR}"
      if [ $? -eq 1 ];then
        echo "addmount call failed, sleep 10s try again"
        sleep 10
      fi
      if [ "x$(nsenter -t $pid -m ls -ll "${SOTHOTH_DIR}/sothoth.conf" 2>/dev/null)" = "x" ];then
        echo "addmount check failed, in docker not exist file: ${SOTHOTH_DIR}/sothoth.conf, sleep 10s try again"
        sleep 10
      else
        break
      fi
    else
      echo "already mount, no need do again"
      break
    fi
  done
}

if [ "$host_pid_ns" != "$process_pid_ns" ]; then
  echo "Process $pid is running inside a container, start add mount for it"
  add_mount_for_container
else
  echo "Process $pid is not running inside a container, ignore add mount for it"
fi


options="-javaagent:${SOTHOTH_DIR}/share/opentelemetry-javaagent.jar"
options="$options -Dotel.resource.attributes=service.name=$(hostname)-$(cat /dev/urandom | od -x | head -1 | awk '{print $2$3}'),service.version=,deployment.environment="
options="$options -Dotel.exporter.otlp.protocol=http/protobuf"
options="$options -Dotel.exporter.otlp.traces.endpoint=http://200.64.0.1:4318/v1/traces"
#options="$options -Dotel.exporter.otlp.metrics.endpoint=http://200.64.0.1:4318"
#options="$options -Dotel.exporter.otlp.logs.endpoint=http://200.64.0.1:4318"
options="$options -Dotel.logs.exporter=none"
options="$options -Dotel.metrics.exporter=none"
#options="$options -Dotel.javaagent.debug=true"


#attach method 1
#echo "Method 1: java -jar /attach_helper.jar -displayName attach_helper.jar -agent-so \"${SOTHOTH_DIR}/share/libreboot_helper.so\" -pid \"$pid\" -options \"${options}\""
#java -jar /attach_helper.jar  -displayName attach_helper.jar -agent-so "${SOTHOTH_DIR}/share/libreboot_helper.so" -pid "$pid" -options "${options}"
#attach method 2
echo "Method 2: \"/host/${SOTHOTH_DIR}/utils/jattach\" \"$pid\" load \"${SOTHOTH_DIR}/share/libreboot_helper.so\" true \"${options}\""
"/host/${SOTHOTH_DIR}/utils/jattach" "$pid" load "${SOTHOTH_DIR}/share/libreboot_helper.so" true "${options}"


if [ $? -eq 0 ];then
  echo "check run load agent success"
else
  echo "check run load agent failed"
fi

while [ "x" = "x" ]
do
  if [ ! -f "/proc/${pid}/status" ];then
    break
  else
    sleep 10
  fi
done
