#!/usr/bin/env python3
import urllib.request, json, sys, time

REPO = "runshine/sothoth"
WORKFLOW = "build-secflow-app-entry-analyse-image.yaml"
url = f"https://api.github.com/repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page=5"

req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "curl"})
with urllib.request.urlopen(req) as resp:
    data = json.load(resp)

runs = data.get("workflow_runs", [])
if not runs:
    print("No runs found")
    sys.exit(0)

for r in runs:
    print(f"run_id={r['id']} status={r['status']} conclusion={r['conclusion']} created={r['created_at']} sha={r['head_sha'][:7]} branch={r['head_branch']}")
