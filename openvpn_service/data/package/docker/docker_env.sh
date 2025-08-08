#!/bin/sh

export DOCKER_ROOT_DIR="$(cd "$(dirname $0)";pwd)/../../docker"

# 创建临时初始化文件
INIT_FILE=$(mktemp)
cat <<EOF > "$INIT_FILE"
alias docker="${DOCKER_ROOT_DIR}/bin/docker -H 'unix:///${DOCKER_ROOT_DIR}/run/docker.sock'"
alias docker-compose="${DOCKER_ROOT_DIR}/../utils/docker-compose -H 'unix:///${DOCKER_ROOT_DIR}/run/docker.sock'"
export TMOUT=0
export HISTSIZE=9999
export HISTFILESIZE=9999
export PROMPT_COMMAND=
export HISTFILE="${DOCKER_ROOT_DIR}/../.bash_history"
EOF
# 启动子 shell 并加载初始化文件
"${DOCKER_ROOT_DIR}/../utils/bash" --rcfile "$INIT_FILE"
# 清理临时文件（可选）
rm -f "$INIT_FILE"