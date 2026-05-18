#!/usr/bin/env python3
"""prefilter.py — 从 manifest.jsonl 筛出真正可能是攻击入口的候选。

确定性规则，不依赖模型。分三层打分：
  tier1  强特征（导出 + 函数 + 名字匹配攻击面正则）
  tier2  中等特征（导出 + 函数 + rodata 引用含入口字符串）
  tier3  弱特征（仅名字匹配，非导出，留作兜底）

用法:
    prefilter.py <run-dir>
输出:
    <run-dir>/candidates.jsonl    每行 {name, addr, size, tier, reason}
    <run-dir>/prefilter_stats.json
"""
import json, re, sys, pathlib, collections

ATTACK_PATTERNS = [
    # 内核 / 驱动 fops 和 ops
    (r"(_fops|_ops)$",                           "ops-table"),
    (r"_ioctl$|_unlocked_ioctl$|_compat_ioctl$", "ioctl-handler"),
    (r"_read$|_write$|_mmap$|_poll$|_release$|_open$", "fops-handler"),
    # 系统服务 / binder / IPC
    (r"^Java_",                                  "jni-export"),
    (r"^JNI_OnLoad$",                            "jni-onload"),
    (r"onTransact|BnTransact|BpTransact",        "binder-transact"),
    (r"dispatch|handle_|handler$|_handler$",     "dispatch"),
    # 协议 / 解析入口
    (r"parse|decode|deserialize|unmarshal|unpack", "parser"),
    (r"recv|ingress|on_packet|on_frame|on_message", "recv-path"),
    # netlink / socket / netdev
    (r"^nl_|_nl_|genl_|_genl_|netlink_",         "netlink"),
    (r"_socket$|_sendmsg$|_recvmsg$|_bind$|_connect$|_accept$", "socket-op"),
    # 厂商定制 / 命令字
    (r"_cmd$|_command$|exec_cmd|cmd_handler",    "cmd-dispatch"),
    (r"service_|_service$|Service$",             "service-entry"),
    # procfs/sysfs 钩子
    (r"_show$|_store$|proc_.*_show",             "sysfs-procfs"),
    # 名字包含 hw/huawei/vendor 的厂商定制
    (r"^hw[A-Z_]|^huawei_|^vendor_|_hw_|_oem_", "vendor-custom"),
]
COMPILED = [(re.compile(p), tag) for p, tag in ATTACK_PATTERNS]

# 明确要丢掉的
DROP_PATTERNS = [
    r"^__",                # 编译器/链接器生成
    r"\.\d+$",             # 内部拷贝
    r"_debug_|_test_|_einj_|__ksymtab|__kcrctab|__param_",
]
DROP = [re.compile(p) for p in DROP_PATTERNS]

# rodata 引用里算入口字符串的 pattern
ROARG = re.compile(r"(/dev/|/proc/|/sys/|/data/|_service$|SERVICE_|NETLINK_|AF_[A-Z]+|ioctl|binder|genl)")


def main():
    if len(sys.argv) != 2:
        print("usage: prefilter.py <run-dir>", file=sys.stderr)
        sys.exit(2)
    run = pathlib.Path(sys.argv[1])
    manifest = run / "manifest.jsonl"
    if not manifest.exists():
        print(f"[-] {manifest} not found, run build_manifest.sh first", file=sys.stderr)
        sys.exit(1)

    strings = {}
    strs = (run / "strings.txt")
    if strs.exists():
        for line in strs.read_text(errors='ignore').splitlines():
            if ROARG.search(line):
                strings[line.strip()] = True

    out = (run / "candidates.jsonl").open("w")
    tier_counts = collections.Counter()
    total = 0
    matched_tags = collections.Counter()

    for line in manifest.open():
        sym = json.loads(line)
        total += 1
        name = sym["name"]
        if any(r.search(name) for r in DROP):
            continue
        # 只看函数符号
        if sym.get("type") not in ("FUNC", "IFUNC", "GNU_IFUNC"):
            continue
        # tier1: 导出 + 名字匹配
        hits = [tag for rx, tag in COMPILED if rx.search(name)]
        is_global = sym.get("bind") in ("GLOBAL", "WEAK") and sym.get("vis") == "DEFAULT"
        if hits and is_global:
            tier, reason = 1, "+".join(hits)
        elif hits:
            tier, reason = 3, "name-match-only:" + "+".join(hits)
        elif is_global and sym.get("size", 0) >= 32:
            tier, reason = 2, "exported-fn"
        else:
            continue
        for h in hits:
            matched_tags[h] += 1
        out.write(json.dumps({
            "name": name,
            "addr": sym["addr"],
            "size": sym["size"],
            "tier": tier,
            "reason": reason,
        }, ensure_ascii=False) + "\n")
        tier_counts[tier] += 1
    out.close()

    stats = {
        "total_symbols": total,
        "candidates": sum(tier_counts.values()),
        "by_tier": dict(tier_counts),
        "by_tag": dict(matched_tags.most_common()),
    }
    (run / "prefilter_stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False))
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
