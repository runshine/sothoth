#!/usr/bin/env python3
"""Poll GitHub Actions run until completed, then trigger k8s rollout."""
import urllib.request, json, sys, time, subprocess, os

REPO = "runshine/sothoth"
WORKFLOW = "build-secflow-app-entry-analyse-image.yaml"
RUN_ID = 25590194213
POLL_INTERVAL = 30  # seconds

url = f"https://api.github.com/repos/{REPO}/actions/runs/{RUN_ID}"

print(f"Monitoring run {RUN_ID}...", flush=True)
while True:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "curl"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.load(resp)
    except Exception as e:
        print(f"  [warn] fetch error: {e}", flush=True)
        time.sleep(POLL_INTERVAL)
        continue

    status = data.get("status")
    conclusion = data.get("conclusion")
    updated = data.get("updated_at", "")
    print(f"  [{updated}] status={status} conclusion={conclusion}", flush=True)

    if status == "completed":
        if conclusion == "success":
            print("CI SUCCESS - proceeding to rollout", flush=True)
        else:
            print(f"CI FAILED with conclusion={conclusion}", flush=True)
            sys.exit(1)
        break

    time.sleep(POLL_INTERVAL)

# Trigger k8s rollout
print("Triggering kubectl rollout restart...", flush=True)
result = subprocess.run(
    ["kubectl", "rollout", "restart", "deployment/secflow-app-entry-analyse", "-n", "secflow-ns"],
    capture_output=True, text=True
)
print(result.stdout.strip())
if result.returncode != 0:
    print(f"ERROR: {result.stderr.strip()}", flush=True)
    sys.exit(1)

# Wait for rollout to complete
print("Waiting for rollout to complete...", flush=True)
result2 = subprocess.run(
    ["kubectl", "rollout", "status", "deployment/secflow-app-entry-analyse", "-n", "secflow-ns", "--timeout=300s"],
    capture_output=True, text=True
)
print(result2.stdout.strip())
if result2.returncode != 0:
    print(f"ERROR: {result2.stderr.strip()}", flush=True)
    sys.exit(1)

# Show new pod
result3 = subprocess.run(
    ["kubectl", "get", "pod", "-n", "secflow-ns", "-l", "app=secflow-app-entry-analyse"],
    capture_output=True, text=True
)
print(result3.stdout.strip())
print("DONE - deployment updated successfully")
