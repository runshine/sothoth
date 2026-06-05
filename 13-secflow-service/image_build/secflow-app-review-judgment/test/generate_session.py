#!/usr/bin/env python3
"""
Generate a fake pi worker session JSONL file that is structurally identical to
real pi --session-dir output, simulating a data-flow vulnerability hunting session.
"""
import json, os, uuid, hashlib
from pathlib import Path

TEST_DIR = Path("/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-review-judgment/test")
SESSION_DIR = TEST_DIR / "session" / "worker-vuln-scan"
SESSION_DIR.mkdir(parents=True, exist_ok=True)
os.makedirs(TEST_DIR / "results", exist_ok=True)
os.makedirs(TEST_DIR / "supporting_docs", exist_ok=True)

SESSION_ID = "019e90ab" + uuid.uuid4().hex[8:12] + "-" + uuid.uuid4().hex[4:8] + "-" + uuid.uuid4().hex[4:8] + "-" + uuid.uuid4().hex[4:8] + "-" + uuid.uuid4().hex[8:]
SESSION_TS = "2026-06-04T05:55:18.148Z"
CWD = str(TEST_DIR)
SRC_DIR = str(TEST_DIR / "source")
DATAFLOW_DIR = str(TEST_DIR / "dataflows")
RESULTS_DIR = str(TEST_DIR / "results")
SUPPORT_DIR = str(TEST_DIR / "supporting_docs")

MODEL_PROVIDER = "local_minimax"
MODEL_ID = "MiniMax/MiniMax-M2.5"
TASK_MD = str(TEST_DIR / "task.md")
FINAL_REPORT = str(TEST_DIR / "dataflows" / "final_report.md")
DF_BUF_PACKET = str(TEST_DIR / "dataflows" / "dataflow" / "IPSEC_SOCK_Buffer_Packet.md")
DF_PIPE_MSG = str(TEST_DIR / "dataflows" / "dataflow" / "IPSEC_SOCKI_PipeMsg.md")

# ---- helpers ----
def m_id():
    return uuid.uuid4().hex[:8]

def cid(label):
    return f"call_{hashlib.md5(label.encode()).hexdigest()[:16]}"

# Read real file contents for tool results
task_text = (TEST_DIR / "dataflows" / "final_report.md").read_text(encoding="utf-8", errors="replace")[:3000]

buf_packet_text = ""
bp = TEST_DIR / "dataflows" / "dataflow" / "IPSEC_SOCK_Buffer_Packet.md"
if bp.exists():
    buf_packet_text = bp.read_text(encoding="utf-8", errors="replace")[:3000]

pipe_msg_text = ""
pm = TEST_DIR / "dataflows" / "dataflow" / "IPSEC_SOCKI_PipeMsg.md"
if pm.exists():
    pipe_msg_text = pm.read_text(encoding="utf-8", errors="replace")[:2000]

src_lines = (TEST_DIR / "source" / "libipsec.c").read_text(encoding="utf-8", errors="replace").splitlines()
src_excerpt = "\n".join(f"{i}: {line}" for i, line in enumerate(src_lines[25470:25530], 25471))
src_ctx = "\n".join(f"{i}: {line}" for i, line in enumerate(src_lines[26810:26860], 26811))

# Write a plausible task.md
(TEST_DIR / "task.md").write_text(f"""# Vulnerability Hunting Task

## Target
Entry function: `IPSEC_SOCKI_PipeMsg` with 61 tracked callees.

## Input
- Dataflow analysis: `{DATAFLOW_DIR}`
- Source code: `{SRC_DIR}` (libipsec.c, libipsec.h, libipsec.asm)

## Requirements
1. Read final_report.md to understand the call chain
2. Read per-function dataflow reports in dataflow/
3. Verify taint paths against actual source code
4. Write confirmed vulnerability reports to results/result_NNN.md
5. Provide full evidence chains from taint source to dangerous sink
""")

# Result 001 content (already exists)
r001 = (TEST_DIR / "results" / "result_001.md").read_text(encoding="utf-8", errors="replace")

# ---- Build events ----
E = []

def mesg(role, content, parent, ts_offset, api_info=None):
    """Add a message event. content is a list of content blocks."""
    mid = m_id()
    msg = {"role": role, "content": content}
    if api_info:
        msg.update(api_info)
    E.append({
        "type": "message", "id": mid, "parentId": parent,
        "timestamp": f"2026-06-04T05:55:{18+ts_offset:02d}.{100+ts_offset*47:03d}Z",
        "message": msg
    })
    return mid

def tool_result(parent, call_id, tool_name, text, ts_offset, is_error=False):
    mid = m_id()
    E.append({
        "type": "message", "id": mid, "parentId": parent,
        "timestamp": f"2026-06-04T05:55:{18+ts_offset:02d}.{200+ts_offset*47:03d}Z",
        "message": {
            "role": "toolResult", "toolCallId": call_id, "toolName": tool_name,
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
            "timestamp": 1750000000000 + ts_offset * 1000
        }
    })
    return mid

def api():
    return {
        "api": "openai-completions", "provider": MODEL_PROVIDER, "model": MODEL_ID,
        "usage": {"input": 5000, "output": 100, "cacheRead": 0, "cacheWrite": 0, "totalTokens": 5100,
                   "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "total": 0}},
        "stopReason": "toolUse",
        "timestamp": 1750000000000,
        "responseId": f"chatcmpl-{uuid.uuid4().hex[:16]}"
    }

# 1. session
E.append({
    "type": "session", "version": 3, "id": SESSION_ID,
    "timestamp": SESSION_TS, "cwd": CWD
})

# 2. model_change
mc_id = m_id()
E.append({
    "type": "model_change", "id": mc_id, "parentId": None,
    "timestamp": "2026-06-04T05:55:18.183Z",
    "provider": MODEL_PROVIDER, "modelId": MODEL_ID
})

# 3. thinking_level_change
th_id = m_id()
E.append({
    "type": "thinking_level_change", "id": th_id, "parentId": mc_id,
    "timestamp": "2026-06-04T05:55:18.183Z", "thinkingLevel": "high"
})

# ---- Round 1: user prompt ----
user_text = (
    "Perform comprehensive data-flow driven vulnerability hunting on the target function.\n\n"
    "## Context\n"
    f"- Cycle: 1\n"
    f"- Task file: {TASK_MD}\n"
    f"- Results dir: {RESULTS_DIR}\n"
    f"- Supporting docs dir: {SUPPORT_DIR}\n"
    f"- Working directory: {CWD}\n\n"
    "## Instructions\n"
    "1. Read the task file to understand the target and scope\n"
    "2. Read the final dataflow report for call chain overview\n"
    "3. For each DIRECT_SINK/USED/EXPORT marker, read the per-function dataflow report\n"
    "4. Verify taint paths against actual source code\n"
    "5. Write confirmed vulnerability reports with complete evidence chains\n"
)

p1 = mesg("user", [{"type": "text", "text": user_text}], th_id, 0)

# ---- Round 2: assistant reads task.md ----
call1 = cid("read_task")
p2 = mesg("assistant", [
    {"type": "thinking", "thinking": "Let me start by reading the task file to understand the target function and scope.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "\n\n"},
    {"type": "toolCall", "id": call1, "name": "read", "arguments": {"path": TASK_MD}}
], p1, 3, api())

p3 = tool_result(p2, call1, "read", task_text, 3)

# ---- Round 3: assistant reads final_report.md ----
call2 = cid("read_final_report")
p4 = mesg("assistant", [
    {"type": "thinking", "thinking": "Now let me read the final dataflow report to understand the entry function and full call chain.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "\n\n"},
    {"type": "toolCall", "id": call2, "name": "read", "arguments": {"path": FINAL_REPORT}}
], p3, 6, api())

final_text = (TEST_DIR / "dataflows" / "final_report.md").read_text(encoding="utf-8", errors="replace")[:4000]
p5 = tool_result(p4, call2, "read", final_text, 6)

# ---- Round 4: assistant reads IPSEC_SOCK_Buffer_Packet dataflow ----
call3 = cid("read_buf_packet_df")
p6 = mesg("assistant", [
    {"type": "thinking", "thinking": "The final report shows IPSEC_SOCK_Buffer_Packet has a DIRECT_SINK at L25491. I need to read the detailed per-function dataflow report to understand the taint path.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "Reading the Buffer_Packet per-function dataflow report...\n"},
    {"type": "toolCall", "id": call3, "name": "read", "arguments": {"path": DF_BUF_PACKET}}
], p5, 9, api())

p7 = tool_result(p6, call3, "read", buf_packet_text, 9)

# ---- Round 5: assistant reads source code around L25491 ----
call4 = cid("read_src_25491")
p8 = mesg("assistant", [
    {"type": "thinking", "thinking": "DIRECT_SINK at L25491: VRP_Malloc_F(RAW_U64(ctx_base, 28), ...). I need to verify this in the actual source code and trace ctx_base origin.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "\n\n"},
    {"type": "toolCall", "id": call4, "name": "read", "arguments": {"path": f"{SRC_DIR}/libipsec.c", "offset": 25470, "limit": 80}}
], p7, 12, api())

p9 = tool_result(p8, call4, "read", src_excerpt, 12)

# ---- Round 6: assistant reads PipeMsg dataflow ----
call5 = cid("read_pipe_msg_df")
p10 = mesg("assistant", [
    {"type": "thinking", "thinking": "To confirm ctx_base is attacker-controlled, I need to trace back through the pipe message chain: IPSEC_SOCKI_PipeMsg -> HandlePipeData -> PipeData -> ProcPipeData -> Buffer_Packet.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "\n\n"},
    {"type": "toolCall", "id": call5, "name": "read", "arguments": {"path": DF_PIPE_MSG}}
], p9, 15, api())

p11 = tool_result(p10, call5, "read", pipe_msg_text, 15)

# ---- Round 7: assistant reads ProcPipeData source ----
call6 = cid("read_procpipe_src")
p12 = mesg("assistant", [
    {"type": "thinking", "thinking": "IPSEC_SOCK_ProcPipeData at L26660 calls IPSEC_SOCK_Buffer_Packet. I need to verify ctx_base is passed from the pipe message handler chain.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "\n\n"},
    {"type": "toolCall", "id": call6, "name": "read", "arguments": {"path": f"{SRC_DIR}/libipsec.c", "offset": 26810, "limit": 50}}
], p11, 18, api())

p13 = tool_result(p12, call6, "read", src_ctx, 18)

# ---- Round 8: assistant writes result_001.md ----
call7 = cid("write_result_001")
p14 = mesg("assistant", [
    {"type": "thinking", "thinking": "Analysis complete. I have confirmed:\n1. ctx_base originates from external pipe message (IPSEC_SOCKI_PipeMsg INPUT-1)\n2. It flows through HandlePipeData -> PipeData -> ProcPipeData -> Buffer_Packet\n3. At L25491, RAW_U64(ctx_base, 28) reads attacker-controlled 64-bit value directly\n4. This value is passed as first argument to VRP_Malloc_F (heap allocation base)\n5. No validation performed on the heap base parameter\n6. This is CWE-822: Untrusted Pointer Dereference, CRITICAL severity\n\nWriting the full vulnerability report.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "Writing vulnerability report to results/result_001.md...\n"},
    {"type": "toolCall", "id": call7, "name": "write",
     "arguments": {"path": f"{RESULTS_DIR}/result_001.md", "content": r001[:500] + "\n...[complete evidence chain]..."}}
], p13, 21, api())

p15 = tool_result(p14, call7, "write", f"File written: results/result_001.md ({len(r001)} bytes)", 21)

# ---- Round 9: assistant writes supporting doc ----
call8 = cid("write_support_doc")
support_content = (
    "# ctx_base+28 Heap Pointer Analysis\n\n"
    "## Call Chain\n"
    "IPSEC_SOCKI_PipeMsg -> IPSEC_SOCKI_HandlePipeData -> IPSEC_SOCKI_PipeData\n"
    "-> IPSEC_SOCK_ProcPipeData -> IPSEC_SOCK_Buffer_Packet\n\n"
    "## Key Evidence\n"
    "- L25491: VRP_Malloc_F(RAW_U64(ctx_base, 28), ...) -- tainted heap base as first arg\n"
    "- L25493-25496: list_node[0/1] writes to attacker-controlled address\n"
    "- L26660: IPSEC_SOCK_ProcPipeData calls IPSEC_SOCK_Buffer_Packet with ctx_base\n"
    "- L26835: ctx_base comes from external pipe message (INPUT-1)\n\n"
    "## Conclusion\n"
    "Attacker controls ctx_base via pipe message injection, which leads to controlled\n"
    "heap allocation base. No validation exists on the heap base parameter.\n"
)
p16 = mesg("assistant", [
    {"type": "thinking", "thinking": "I should also write an auxiliary analysis document providing detailed trace target analysis.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": "\n\n"},
    {"type": "toolCall", "id": call8, "name": "write",
     "arguments": {"path": f"{SUPPORT_DIR}/result_001_ctx_base28_analysis.md", "content": support_content}}
], p15, 24, api())

p17 = tool_result(p16, call8, "write", f"File written: supporting_docs/result_001_ctx_base28_analysis.md", 24)

# ---- Round 10: Final assistant summary ----
final_text = (
    "## Vulnerability Analysis Complete\n\n"
    "### Findings\n\n"
    "**result_001**: Controlled Heap Pointer via Tainted ctx_base+28 in IPSEC_SOCK_Buffer_Packet\n\n"
    "| Dimension | Assessment |\n"
    "|-----------|------------|\n"
    "| Type | CWE-822: Untrusted Pointer Dereference |\n"
    "| Severity | CRITICAL (CVSS 9.1) |\n"
    "| Confidence | 70% (VRP_Malloc_F internals not audited) |\n"
    "| Attack Surface | Remote (pipe message injection) |\n\n"
    "**Evidence Chain**:\n"
    "1. External pipe message -> IPSEC_SOCKI_PipeMsg (INPUT-1: ctx_base)\n"
    "2. ctx_base -> HandlePipeData -> PipeData -> ProcPipeData\n"
    "3. ProcPipeData (L26660) -> Buffer_Packet (L25491)\n"
    "4. RAW_U64(ctx_base, 28) -> VRP_Malloc_F arg1 (DIRECT_SINK)\n"
    "5. No ctx_base value validation exists\n\n"
    "**Impact**:\n"
    "- Heap allocation redirected to arbitrary address\n"
    "- list_node[0/1] writes corrupt target memory\n"
    "- Potential code execution risk\n\n"
    "**Output Files**:\n"
    "- results/result_001.md -- Full vulnerability report\n"
    "- supporting_docs/result_001_ctx_base28_analysis.md -- Supporting analysis\n"
)

final_api = {
    "api": "openai-completions", "provider": MODEL_PROVIDER, "model": MODEL_ID,
    "usage": {"input": 31234, "output": 456, "cacheRead": 0, "cacheWrite": 0, "totalTokens": 31690,
               "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "total": 0}},
    "stopReason": "stop",
    "timestamp": 1750000030000,
    "responseId": f"chatcmpl-{uuid.uuid4().hex[:16]}"
}

p18 = mesg("assistant", [
    {"type": "thinking", "thinking": "All analysis complete. One CRITICAL vulnerability confirmed with full evidence chain from taint source to dangerous sink.\n", "thinkingSignature": "reasoning_content"},
    {"type": "text", "text": final_text}
], p17, 27, final_api)

# ---- Write JSONL ----
jsonl_name = SESSION_TS.replace(":", "-").replace(".", "-") + "_" + SESSION_ID + ".jsonl"
jsonl_path = SESSION_DIR / jsonl_name
with open(jsonl_path, "w", encoding="utf-8") as f:
    for e in E:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")

# Verify: re-read and check each line is valid JSON
with open(jsonl_path, "r") as f:
    for i, line in enumerate(f, 1):
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"ERROR at line {i}: {exc}")
            raise SystemExit(1)

# Verify structural requirements
lines = [json.loads(l) for l in open(jsonl_path)]
types = [l["type"] for l in lines]
assert types[0] == "session", f"First event must be session, got {types[0]}"
assert types[1] == "model_change", f"2nd event must be model_change"
assert types[2] == "thinking_level_change", f"3rd event must be thinking_level_change"
msg_events = [l for l in lines if l["type"] == "message"]
user_events = [m for m in msg_events if m["message"]["role"] == "user"]
asst_events = [m for m in msg_events if m["message"]["role"] == "assistant"]
tool_events = [m for m in msg_events if m["message"]["role"] == "toolResult"]

print(f"JSONL written: {jsonl_path}")
print(f"Size: {jsonl_path.stat().st_size} bytes")
print(f"Lines: {len(lines)}")
print(f"  session: 1")
print(f"  model_change: 1")
print(f"  thinking_level_change: 1")
print(f"  user messages: {len(user_events)}")
print(f"  assistant messages: {len(asst_events)}")
print(f"  toolResult messages: {len(tool_events)}")

# Check all session events have required fields
for e in [l for l in lines if l["type"] == "session"]:
    assert "version" in e and "id" in e and "cwd" in e, "session missing fields"

print("\nAll validations passed!")