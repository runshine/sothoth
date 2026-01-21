#!/bin/bash
# metallb-diagnosis.sh

echo "=== MetalLB 诊断脚本 ==="
echo ""

echo "1. 检查 MetalLB 命名空间"
kubectl get ns metallb-system

echo ""
echo "2. 检查 MetalLB Pod 状态"
kubectl get pods -n metallb-system -o wide

echo ""
echo "3. 检查控制器日志"
kubectl logs -n metallb-system deployment/controller --tail=20

echo ""
echo "4. 检查 Speaker 日志"
for pod in $(kubectl get pods -n metallb-system -l component=speaker -o name); do
  echo "--- $pod ---"
  kubectl logs -n metallb-system $pod --tail=10 | grep -E "config|announc|service"
done

echo ""
echo "5. 检查 LoadBalancer 服务"
kubectl get svc -A | grep LoadBalancer

echo ""
echo "6. 检查特定服务详情"
SERVICE_NAME=$(kubectl get svc -A | grep LoadBalancer | head -1 | awk '{print $2}')
NAMESPACE=$(kubectl get svc -A | grep LoadBalancer | head -1 | awk '{print $1}')
if [ ! -z "$SERVICE_NAME" ]; then
  kubectl describe svc $SERVICE_NAME -n $NAMESPACE
fi

echo ""
echo "7. 检查节点网络"
echo "节点 IP 地址:"
kubectl get nodes -o wide | awk '{print $1, $6, $7}'

echo ""
echo "8. 检查 MetalLB ConfigMap"
kubectl get configmap config -n metallb-system -o yaml

echo ""
echo "9. 测试连通性"
EXTERNAL_IP=$(kubectl get svc $SERVICE_NAME -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
if [ ! -z "$EXTERNAL_IP" ]; then
  echo "尝试连接 $EXTERNAL_IP"
  for port in 80 443; do
    echo -n "端口 $port: "
    timeout 2 bash -c "echo >/dev/tcp/$EXTERNAL_IP/$port" && echo "开放" || echo "关闭"
  done
fi