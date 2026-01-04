#!/bin/bash
# copy-to-pvc.sh - 将本地文件夹拷贝到指定的PVC中

set -e

# 配置参数
LOCAL_DIR="./resource"
PVC_NAME="sothothv2-client-script-service-nfs-pv"
POD_NAME="copy-pod-$(date +%s)"
NAMESPACE="default"  # 根据实际情况修改命名空间
MOUNT_PATH="/data"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 检查依赖
check_dependencies() {
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl 未安装或不在PATH中"
        exit 1
    fi
}

# 检查K8S连接
check_k8s_connection() {
    if ! kubectl cluster-info &> /dev/null; then
        log_error "无法连接到Kubernetes集群"
        exit 1
    fi
}

# 检查本地目录
check_local_dir() {
    if [ ! -d "$LOCAL_DIR" ]; then
        log_error "本地目录不存在: $LOCAL_DIR"
        exit 1
    fi

    if [ -z "$(ls -A "$LOCAL_DIR" 2>/dev/null)" ]; then
        log_warn "本地目录为空: $LOCAL_DIR"
        read -p "是否继续? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "操作已取消"
            exit 0
        fi
    fi

    log_info "找到以下文件:"
    find "$LOCAL_DIR" -type f | sed "s|^$LOCAL_DIR/||" | head -20
    local count=$(find "$LOCAL_DIR" -type f | wc -l)
    if [ $count -gt 20 ]; then
        echo "... 还有 $((count - 20)) 个文件"
    fi
}

# 检查PVC是否存在
check_pvc() {
    log_info "检查PVC: $PVC_NAME (命名空间: $NAMESPACE)"

    if ! kubectl get pvc "$PVC_NAME" -n "$NAMESPACE" &> /dev/null; then
        log_error "PVC $PVC_NAME 在命名空间 $NAMESPACE 中不存在"
        echo "可用的PVC:"
        kubectl get pvc -n "$NAMESPACE" 2>/dev/null || kubectl get pvc --all-namespaces
        exit 1
    fi

    # 获取PVC状态
    local pvc_status=$(kubectl get pvc "$PVC_NAME" -n "$NAMESPACE" -o jsonpath='{.status.phase}')
    if [ "$pvc_status" != "Bound" ]; then
        log_warn "PVC状态不是Bound (当前状态: $pvc_status)"
        read -p "是否继续? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "操作已取消"
            exit 0
        fi
    fi
}

# 创建临时Pod
create_temp_pod() {
    log_info "创建临时Pod: $POD_NAME"

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $POD_NAME
  namespace: $NAMESPACE
  labels:
    app: file-copier
    temporary: "true"
spec:
  containers:
  - name: busybox
    image: busybox:latest
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: data-volume
      mountPath: $MOUNT_PATH
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: $PVC_NAME
  restartPolicy: Never
EOF

    # 等待Pod变为Running状态
    log_info "等待Pod启动..."
    local attempts=0
    local max_attempts=30

    while [ $attempts -lt $max_attempts ]; do
        local pod_status=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")

        if [ "$pod_status" = "Running" ]; then
            log_info "Pod已启动并运行"
            return 0
        elif [ "$pod_status" = "Failed" ] || [ "$pod_status" = "Error" ]; then
            log_error "Pod启动失败: $pod_status"
            kubectl describe pod "$POD_NAME" -n "$NAMESPACE" | tail -20
            return 1
        fi

        attempts=$((attempts + 1))
        echo -n "."
        sleep 2
    done

    log_error "Pod启动超时"
    kubectl describe pod "$POD_NAME" -n "$NAMESPACE" | tail -30
    return 1
}

# 拷贝文件到PVC
copy_files_to_pvc() {
    log_info "开始拷贝文件到PVC..."

    # 首先检查Pod内容器
    local container_name=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].name}')

    # 清空目标目录（可选）
    read -p "是否清空PVC中的目标目录 $MOUNT_PATH? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "清空目标目录..."
        kubectl exec "$POD_NAME" -n "$NAMESPACE" -c "$container_name" -- sh -c "rm -rf $MOUNT_PATH/* 2>/dev/null || true"
    fi

    # 创建目标目录结构（如果需要）
    kubectl exec "$POD_NAME" -n "$NAMESPACE" -c "$container_name" -- mkdir -p "$MOUNT_PATH"

    # 拷贝文件
    log_info "正在拷贝文件..."

    # 计算文件数量
    local file_count=$(find "$LOCAL_DIR" -type f | wc -l)
    local processed=0

    # 使用find命令遍历所有文件并逐个拷贝
    find "$LOCAL_DIR" -type f | while read -r file; do
        processed=$((processed + 1))
        # 计算相对路径
        rel_path="${file#$LOCAL_DIR/}"
        # 创建目标目录
        target_dir="$MOUNT_PATH/$(dirname "$rel_path")"

        echo -ne "\r拷贝文件: $processed/$file_count - $rel_path"

        # 确保目标目录存在
        kubectl exec "$POD_NAME" -n "$NAMESPACE" -c "$container_name" -- mkdir -p "$target_dir" 2>/dev/null || true

        # 拷贝文件
        kubectl cp "$file" "$NAMESPACE/$POD_NAME:$target_dir/$(basename "$file")" -c "$container_name" >/dev/null 2>&1 || {
            echo ""
            log_warn "拷贝失败: $rel_path"
        }
    done

    echo ""
    log_info "文件拷贝完成"

    # 验证拷贝结果
    log_info "验证拷贝结果..."
    kubectl exec "$POD_NAME" -n "$NAMESPACE" -c "$container_name" -- find "$MOUNT_PATH" -type f | wc -l | while read count; do
        log_info "PVC中现有文件数量: $count"
    done
}

# 清理临时Pod
cleanup_temp_pod() {
    log_info "清理临时Pod: $POD_NAME"
    kubectl delete pod "$POD_NAME" -n "$NAMESPACE" --force --grace-period=0 2>/dev/null || true
}

# 显示帮助
show_help() {
    cat << EOF
使用: $(basename "$0") [选项]

将本地文件夹拷贝到Kubernetes PVC中

选项:
  -d, --dir DIR         本地目录路径 [默认: ./resource]
  -p, --pvc PVC_NAME    PVC名称 [默认: sothothv2-client-script-service-nfs-pv]
  -n, --namespace NS    命名空间 [默认: default]
  -m, --mount-path PATH 挂载路径 [默认: /mnt/data]
  -h, --help            显示此帮助信息

示例:
  $(basename "$0") -d ./data -p my-pvc -n my-namespace
  $(basename "$0") --dir ./config --pvc app-data --namespace production

EOF
}

# 参数解析
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dir)
                LOCAL_DIR="$2"
                shift 2
                ;;
            -p|--pvc)
                PVC_NAME="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -m|--mount-path)
                MOUNT_PATH="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 主函数
main() {
    # 解析参数
    parse_args "$@"

    # 检查依赖
    check_dependencies

    # 检查K8S连接
    check_k8s_connection

    # 检查本地目录
    check_local_dir

    # 检查PVC
    check_pvc

    # 确认操作
    echo ""
    echo "========================================"
    echo "操作摘要:"
    echo "  本地目录: $LOCAL_DIR"
    echo "  PVC名称: $PVC_NAME"
    echo "  命名空间: $NAMESPACE"
    echo "  挂载路径: $MOUNT_PATH"
    echo "========================================"
    echo ""

    read -p "确认执行拷贝操作? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "操作已取消"
        exit 0
    fi

    # 创建临时Pod
    if ! create_temp_pod; then
        log_error "创建临时Pod失败"
        exit 1
    fi

    # 设置trap确保清理
    trap 'log_warn "中断信号，清理临时Pod..."; cleanup_temp_pod; exit 1' INT TERM

    # 拷贝文件
    if ! copy_files_to_pvc; then
        log_error "拷贝文件失败"
        cleanup_temp_pod
        exit 1
    fi

    # 清理临时Pod
    cleanup_temp_pod

    log_info "✅ 操作完成！文件已成功拷贝到PVC: $PVC_NAME"

    # 显示PVC信息
    echo ""
    log_info "PVC状态:"
    kubectl get pvc "$PVC_NAME" -n "$NAMESPACE" -o wide
}

# 执行主函数
main "$@"