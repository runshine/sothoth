#!/usr/bin/env pwsh
# deploy_and_monitor.ps1
# 用法: .\patch_build\deploy_and_monitor.ps1 [-Service system-analyse]
# 每次修改代码后：在子模块内 commit & push，然后运行此脚本
# 它会：1) 等待 CI 触发并构建成功  2) 更新 K8s 镜像  3) 监控到 pod Running

param(
    [string]$Service = "system-analyse"
)

$key      = "$env:USERPROFILE\.ssh\id_yyf_188"
$k8sHost  = "icsl@172.31.23.188"
$today    = (Get-Date).ToString("yyyyMMdd")

$workflowMap = @{
    "system-analyse"   = "build-secflow-app-system-analyse-image.yaml"
    "entry-analyse"    = "build-secflow-app-entry-analyse-image.yaml"
    "dataflow-analyse" = "build-secflow-app-dataflow-analyse-image.yaml"
}
$deploymentMap = @{
    "system-analyse"   = @{ dep = "secflow-app-system-analyse";   ns = "secflow-ns"; container = "secflow-app-system-analyse";   image = "ghcr.io/runshine/secflow-app-system-analyse:amd64-$today" }
    "entry-analyse"    = @{ dep = "secflow-app-entry-analyse";     ns = "secflow-ns"; container = "secflow-app-entry-analyse";     image = "ghcr.io/runshine/secflow-app-entry-analyse:amd64-$today" }
    "dataflow-analyse" = @{ dep = "secflow-app-dataflow-analyse";  ns = "secflow-ns"; container = "secflow-app-dataflow-analyse";  image = "ghcr.io/runshine/secflow-app-dataflow-analyse:amd64-$today" }
}

$workflow   = $workflowMap[$Service]
$deployment = $deploymentMap[$Service]

if (-not $workflow -or -not $deployment) {
    Write-Host "未知服务: $Service。可用: $($workflowMap.Keys -join ', ')" -ForegroundColor Red
    exit 1
}

$ghApiBase = "https://api.github.com/repos/runshine/sothoth/actions"
$headers   = @{ "Accept" = "application/vnd.github+json" }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " 部署监控: $Service" -ForegroundColor Cyan
Write-Host " 目标镜像: $($deployment.image)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── 阶段 1: 获取当前最新 run ID ──────────────────────────────────────────────
$runs    = Invoke-RestMethod -Uri "$ghApiBase/workflows/$workflow/runs?per_page=1&branch=v2.1" -Headers $headers
$oldRunId = $runs.workflow_runs[0].id
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 当前最新 run: $oldRunId"
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 等待新 CI run 触发 (最长 5 min)..."

$newRunId = $null
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 15
    $runs   = Invoke-RestMethod -Uri "$ghApiBase/workflows/$workflow/runs?per_page=1&branch=v2.1" -Headers $headers
    $latest = $runs.workflow_runs[0]
    if ($latest.id -gt $oldRunId) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ✓ 新 run 触发: $($latest.id)" -ForegroundColor Green
        $newRunId = $latest.id
        break
    }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 等待中... (仍是 $($latest.id))"
}
if (-not $newRunId) {
    Write-Host "超时未触发，请确认已 push 到 v2.* 分支且路径匹配 workflow paths" -ForegroundColor Red
    exit 1
}

# ── 阶段 2: 等待 CI 构建完成 ─────────────────────────────────────────────────
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 等待构建完成 (预计 5-15 min)..."
$ciOk = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 30
    $run = Invoke-RestMethod -Uri "$ghApiBase/runs/$newRunId" -Headers $headers
    $t   = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$t] CI: $($run.status) / $($run.conclusion)"
    if ($run.status -eq "completed") {
        if ($run.conclusion -eq "success") {
            Write-Host "[$t] ✓ 构建成功" -ForegroundColor Green
            $ciOk = $true
        } else {
            Write-Host "[$t] ✗ 构建失败: $($run.conclusion)  链接: $($run.html_url)" -ForegroundColor Red
        }
        break
    }
}
if (-not $ciOk) { Write-Host "CI 未成功完成" -ForegroundColor Red; exit 1 }

# ── 阶段 3: 更新 K8s 镜像 ───────────────────────────────────────────────────
$dep       = $deployment.dep
$ns        = $deployment.ns
$container = $deployment.container
$image     = $deployment.image

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 更新 K8s 镜像..." -ForegroundColor Yellow
$result = ssh -i $key $k8sHost "kubectl set image deployment/$dep ${container}=$image -n $ns 2>&1"
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $result"

# ── 阶段 4: 监控 rollout ─────────────────────────────────────────────────────
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 监控 rollout..." -ForegroundColor Yellow
$rollout = ssh -i $key $k8sHost "kubectl rollout status deployment/$dep -n $ns --timeout=180s 2>&1"
Write-Host $rollout

$pod = ssh -i $key $k8sHost "kubectl get pods -n $ns -l app=$dep --no-headers 2>&1"
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Pod 状态: $pod"

if ($rollout -match "successfully rolled out") {
    Write-Host ""
    Write-Host "✓ 部署完成: $image" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "✗ Rollout 未成功完成，请手动检查" -ForegroundColor Red
    exit 1
}
