#!/bin/sh

ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"
cd "$(cd "$(dirname $0)";pwd)"
. "${ROOT_DIR}/script/common.sh"

# 创建临时初始化文件
INIT_FILE=$(mktemp)
cat <<EOF > "$INIT_FILE"
alias docker="${ROOT_DIR}/usr/bin/docker -H 'unix:///${ROOT_DIR}/var/run/docker.sock'"
alias docker-compose="${ROOT_DIR}/usr/bin/docker-compose -H 'unix:///${ROOT_DIR}/var/run/docker.sock'"
export TMOUT=0
export HISTSIZE=9999
export HISTFILESIZE=9999
export PROMPT_COMMAND=
export HISTFILE="${ROOT_DIR}/var/run/.bash_history"
export HOME="${ROOT_DIR}"
export PS1='(v2)\u@\h:\w# '
EOF
# 启动子 shell 并加载初始化文件
"${ROOT_DIR}/bin/bash" --rcfile "$INIT_FILE"
# 清理临时文件（可选）
rm -f "$INIT_FILE"