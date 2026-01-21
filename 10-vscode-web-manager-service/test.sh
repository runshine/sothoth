#!/bin/bash
# debug-traefik-nginx.sh
echo "=== 完整的 NGINX -> Traefik 调试脚本 ==="

echo -e "\n1. 检查所有相关组件状态:"
echo "--- Traefik Service ---"
kubectl describe svc traefik -n kube-system

echo -e "\n--- NGINX ExternalName Service ---"
kubectl describe svc traefik -n ingress-nginx 2>/dev/null || echo "Service not found"

echo -e "\n--- Traefik Ingress ---"
kubectl describe ingress code-ingress-3f070980 -n vscode

echo -e "\n--- vscode Service ---"
kubectl describe svc code-svc-3f070980 -n vscode

echo -e "\n2. 测试 DNS 解析:"
kubectl run -it --rm --image=busybox dns-test -- \
  sh -c "echo 'Testing traefik.kube-system.svc.cluster.local:'; nslookup traefik.kube-system.svc.cluster.local; echo 'Testing traefik.ingress-nginx.svc.cluster.local:'; nslookup traefik.ingress-nginx.svc.cluster.local"

echo -e "\n3. 测试直接访问 Traefik:"
echo "测试命令: curl -v -H 'Host: 3f070980.code-server.sothothv2.com' http://192.168.12.190/"
read -p "执行测试？(y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    curl -v -H "Host: 3f070980.code-server.sothothv2.com" http://192.168.12.190/
fi

echo -e "\n4. 测试从 NGINX Pod 访问 Traefik:"
NGINX_POD=$(kubectl get pod -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
echo "NGINX Pod: $NGINX_POD"
kubectl exec -n ingress-nginx $NGINX_POD -- \
  curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
  -H "Host: 3f070980.code-server.sothothv2.com" \
  http://traefik.kube-system.svc.cluster.local

echo -e "\n5. 查看 Traefik 日志:"
kubectl logs -n kube-system -l app.kubernetes.io/name=traefik --tail=20

echo -e "\n6. 查看 NGINX 日志:"
kubectl logs -n ingress-nginx -l app.kubernetes.io/component=controller --tail=10