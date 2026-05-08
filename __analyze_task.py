import json, subprocess, sys

r = subprocess.run(
    ["curl", "-sk", "https://secflow.ai.icsl.huawei.com/api/app/entry-analyse/tasks/eat_079b99042a5246bd"],
    capture_output=True
)
data = json.loads(r.stdout)
events = data.get("stages_json", {}).get("events", [])
print("total:", len(events))
print("status:", data["status"])
print("error:", data.get("error"))
print("--- last 6 events ---")
for e in events[-6:]:
    print(" ", e["type"], str(e.get("data",""))[:120])
print("--- round/judge/resume events ---")
KEY = ["round_start","master_worker_start","master_worker_done","judge_start","judge_done","workers_skipped","task_resume_workers"]
for e in events:
    if e["type"] in KEY:
        print(" ", e["type"], str(e.get("data",""))[:120])
print("--- worker_done count ---")
wdone = [e for e in events if e["type"] == "worker_done"]
print(" worker_done count:", len(wdone))
if wdone:
    last = wdone[-1]
    print(" last worker_done data:", str(last.get("data",""))[:120])
