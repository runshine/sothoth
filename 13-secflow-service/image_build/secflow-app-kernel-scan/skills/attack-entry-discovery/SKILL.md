---
name: attack-entry-discovery
description: 当需要从源码或二进制中系统化查找攻击入口时使用。覆盖 Linux/Android/Harmony 内核、驱动、系统服务、native daemon、共享库与可执行文件，目标是识别所有外部可触达的输入面，不用管需要什么权限，如 ioctl/read/write/mmap、procfs/sysfs/debugfs、netlink、binder、socket、系统调用、协议解析入口、JNI/IPC/exported 组件等。
---

# 攻击入口发现

## 适用场景

在以下场景触发：

- 用户要求“找攻击面”“找入口点”“梳理可达接口”
- 用户明确要求“所有文件”“全量扫描”“整个目录都要处理”
- 需要从源码中枚举用户态到内核/服务的输入入口
- 需要从二进制中逆向导出命令处理函数、IPC 接口、协议解析入口
- 在漏洞挖掘前先做 attack surface mapping

## 核心目标

输出**所有**的外部可达的攻击入口，一定要找出具体的驱动路径、设备节点、服务名、协议号或命令字，而不是机械罗列所有 API。不要输出 `einj`、`debug`、`test` 等调试模块入口。

优先回答：

1. 入口是什么？驱动节点/文件节点名字。
3. 通过什么系统调用能访问。


如果用户明确要求“所有文件”或“全量”，还要额外满足：

5. 必须给出可校验的覆盖率结果，证明没有漏扫
6. 在 `missing > 0` 时，不得声称“已处理全部文件”

## 标准 Prompt 模板

优先复用下面这条标准模板，不要每次临时拼很长的 prompt：

```text
使用 $attack-entry-discovery 对 <目标> 做攻击入口分析。若 <目标> 是源码目录，处理其中所有文件，不要只扫命中的候选文件；若是二进制，按注册点、ops 结构体、handler 的链路恢复真实入口。只输出真实外部可达入口，过滤 einj、debug、test-only 等低价值接口。对每个入口写清位置、节点/服务/协议/命令、用户态触发方式、权限、普通 app/shell/网络对端可达性，以及是否值得继续验证。优先输出厂商定制业务，报告写到 ./AI4Vul/AS_<model>_<time>.md。
```

常用替换项：

- `<目标>`：源码目录、单个子目录、`vmlinux`、`.ko`、解包后的内核镜像产物
- 如果用户明确要求“全量”，在 `<目标>` 后补一句：`必须处理所有文件，并给出覆盖情况。`

## 总体方法

### 一、先界定目标与攻击者模型

开始前先明确：

- 目标类型：内核、驱动、守护进程、系统服务、共享库、协议栈
- 输入来源：普通 app、shell、非 root 用户、蓝牙/Wi‑Fi/USB/基带/网络对端、本地 IPC 调用者

### 二、全量模式（用户要求“所有文件”时强制启用）

这部分是**硬约束**。只要用户要求“所有文件”“全量”“整个目录”，必须先做这里，再开始正常的入口分析。
用户需要分析所有文件时，加载`references/all_file_model.md`

### 三、分析对象画像
查看分析对象是源码还是二进制，如果是源码，则参考`四、源码分析路径`，如果是二进制，则参考`五、二进制分析路径`

### 四、源码分析路径
当用户需要对源码进行分析时，加载`references/source_code_scan_sheet.md`

### 五、二进制分析路径
当用户需要对二进制进行攻击入口分析时，加载`references/binary_scan_sheet.md`


## 推荐执行顺序
尽可能多的找出攻击入口，不需要区分是否为高价值入口，

如果是全量模式，执行顺序固定为：

1. 生成 manifest 和 batch
2. 按 batch 推进源码/二进制入口分析
3. 每批处理后更新回执
4. 对 `skipped` / `error` 文件补原因
5. 运行 `verify`，确认 `missing == 0`
6. 再汇总攻击入口报告

如果不是全量模式，再按下面的一般顺序执行：

1. 盘点目录/二进制类型
2. 大范围 grep/字符串扫描找入口模式
3. 缩小到候选 handler/注册点
4. 读取上下文，恢复“入口名 → handler → 危险数据流”
5. 提取设备节点、服务名、协议号、URI、action、事务码
6. 实机检查权限与存在性
7. 若需要，用普通 app 或 shell 做最小访问验证
8. 输出按“真实可达性”排序的攻击入口报告

## 输出要求

最终报告输出到 `./AI4Vul`，报告命名规则：`AS_<model-name>_<module-name>_<time>.md`，厂商定制的业务排前面，业界通用的排后面：

直接输出所有攻击入口列表，每一项攻击入口要包括三部分，不要输出其他多余的，每一行的格式：
`函数名  [类型]`

比如：
```bash
binder_ioctl  [ioctl]
vfs_read      [read]
hvgr_ioctl    [ioctl]
```

## 产出风格
- 优先中文


## 常见坑

- 用户要求“所有文件”，却仍然只扫 grep 命中的候选文件
- 先按 `.c/.h` 过滤，导致 `Kconfig`、`Makefile`、`dts/dtsi`、`.S` 根本没进扫描集合
- 只列注册点，不追 handler 和数据流
- 二进制里只看字符串，不回溯交叉引用
- 把 debugfs、测试接口、编译期可选功能误判成量产攻击面
- 忽略 manifest/exported/permission 导致 app 侧判断失真
- 只统计“已处理文件”，不统计 `skipped/error/missing`
- `verify` 还没通过就输出“全量扫描完成”
- **cwd 漂移**：大型 `vmlinux` 分析需要很多步，终端 cwd 可能中途改变导致后续所有 `nm`/`strings` 全部报 `No such file`。开头就用绝对路径变量锁定目标文件
- **并行扫描时用 execute_code**：439+ `fops`、790 `syscalls` 这种量级的符号分类，应当用 `execute_code` 写 Python 脚本一次性完成分类汇总，而不是反复用 terminal 逐条 grep，后者既慢又容易因 cwd 问题中断
- **terminal 输出截断**：`terminal()` 和 `execute_code` 内的 `terminal()` 都有输出长度上限（约 50KB）。对 220K+ 符号的 `vmlinux`，`nm` 的直接输出会被截断到约 1300 行。解决方案：先用 shell 重定向把完整输出写到临时文件（`nm "$VMLINUX" > /tmp/vmlinux_syms.txt`），再用 `grep` 按类别过滤到多个小文件（`grep '_fops' /tmp/vmlinux_syms.txt > /tmp/vm_fops.txt`），后续所有分析都基于这些中间文件。绝不要在 `execute_code` 里通过 `terminal('nm ...')` 读取大量符号然后在 Python 中处理
- **macOS grep 无 -P 选项**：macOS 的 BSD grep 不支持 Perl 正则（`-P`），用 `sed` / `awk` 替代。例如提取 syscall 名：`awk '{print $3}' | sed 's/__arm64_sys_//'`，而非 `grep -oP '__arm64_sys_\\K...'`
- **子任务并行委派**：对于大型 `vmlinux`（220K+ 符号），将分析拆成 3 个并行子任务效果最好：(1) `fops`/设备注册分析 (2) 厂商定制子系统分析 (3) `syscall`/`ioctl`/`netlink`/`binder` 分析。用并行子任务读取预先 grep 好的中间文件

## 参考文件
- 全量模式说明：`references/usage.md`
- 命令速查：`references/command-cheatsheet.md`
- 完备性脚本：`scripts/completeness_guard.py`
- 二进制扫描说明：`references/binary_scan_sheet.md` 
- 源码扫描说明：`references/source_code_scan_sheet.md`

## 与其他 skill 的配合

- **大型 ELF 专用子流程**：`large-binary-attack-surface`。当二进制 ≥ 50MB，或符号数 ≥ 20000，或是 `vmlinux` / 巨型 `.so` / 大 daemon 时，不要用本 skill 的 `binary_scan_sheet.md`，改走它的 manifest→预过滤→分批→回执→覆盖率校验流水线。
- 需要写 App 内 JNI 探测器验证普通 app 可达性时：`app-jni-poc-verification`
- 需要把确认的入口做成可运行 PoC 时：`poc-verification`
- 需要针对内核源码继续挖漏洞时：可配合内核审计类 agent/skill
