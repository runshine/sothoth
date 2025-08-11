#!/bin/sh

pid="$1"
echo "start add mount for docker sence"
/addmount 1 "${SOTHOTH_DIR}" "$pid" "${SOTHOTH_DIR}"

echo "java -jar /attach_helper.jar -options 'sothoth_dir=${SOTHOTH_DIR}' -displayName attach_helper.jar -agent-so \"${SOTHOTH_DIR}/share/libreboot_helper.so\" -pid \"$pid\""
java -jar /attach_helper.jar -options "sothoth_dir=${SOTHOTH_DIR}" -displayName attach_helper.jar -agent-so "${SOTHOTH_DIR}/share/libreboot_helper.so" -pid "$pid"
if [ $? -eq 0 ];then
  echo "run load agent success"
else
  echo "run load agent failed"
fi

while [ "x" = "x" ]
do
  if [ ! -f "/proc/${pid}/status" ];then
    break
  else
    sleep 10
  fi
done