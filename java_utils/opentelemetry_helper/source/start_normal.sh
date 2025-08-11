#!/bin/sh

pid="$1"
if [ "x${pid}" = "x" ];then
  echo "You must input pid"
  exit 255
fi
nspid="$(cat "/proc/${pid}/status" | grep NSpid | awk '{print $2}')"
if [ "x${nspid}" = "x" ] || [ "x${pid}" != "x${nspid}" ];then
  echo "Pid error, not exist or in docker: ${pid}"
  exit 255
fi

#java -jar agent-attach-java.jar -options 'dd.service=test,dd.tag=v1' -displayName tmall.jar -agent-jar /usr/local/ddtrace/dd-java-agent.jar
java -jar /attach_helper.jar -options 'dd.service=test,dd.tag=v1' -displayName attach_helper.jar -agent-so /libreboot_helper.so