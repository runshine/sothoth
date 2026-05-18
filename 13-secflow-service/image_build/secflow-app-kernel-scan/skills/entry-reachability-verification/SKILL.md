---
name: entry-reachability-verification
description: 当已经从源码、二进制或报告中识别出攻击入口，需要编写最小 PoC 或探测程序，验证该入口是否能被普通 app、adb shell、或其他低权限上下文访问时使用。适用于 /dev、/proc、/sys、ioctl、read/write、mmap、netlink、binder、socket、exported 组件等入口的可达性验证与结果归类。
---

# 攻击入口可达性验证

## 适用场景

在以下场景触发：

- 已经找到了攻击入口，但还不确定谁能真正访问
- 需要判断某入口是否是：
  - 普通 app 可达
  - adb shell 可达
  - system/特权进程可达
  - 网络对端可达
- 需要把“源码里存在入口”收敛为“真实可打到的入口”
- 需要为后续漏洞 PoC 提供访问前置验证

这个 skill 的重点不是直接触发漏洞，而是验证“入口是否能到达”。

如果已经明确漏洞点并要做完整漏洞触发 PoC，优先配合：
- `poc-verification`

如果要在 App/Hap中以普通应用身份验证入口，优先配合：
- `app-jni-poc-verification`

## 核心目标

对每个候选入口，最终明确回答：

1. 设备上是否存在
2. shell 是否可达
3. 普通 app 是否可达
4. 是否需要额外权限、group、SELinux 域、signature/system 权限
5. 最终归类为：
   - app 可达
   - shell 可达但 app 不可达
   - system/特权可达
   - 不可达/节点不存在

## 输入信息

开始前尽量收集：

- 入口类型：`/dev`、`/proc`、`/sys`、`ioctl`、`mmap`、`netlink`、`binder`、`socket`、`intent/provider`
- 入口名称：ioctl命令、路径、协议号、family 名、service 名、URI、action、组件名
- 目标设备类型：Android / Harmony
- 关注攻击者：普通 app、shell、网络对端
- 是否已有参考工程（例如 AppPoc）

如果用户没指定，默认优先验证顺序：

1. 节点/服务是否存在
2. adb shell 是否可达
3. 普通 app 是否可达
4. 必要时再看 system/特权上下文

## 方法总览

按“存在性 → shell → app → 分类结论”的顺序执行。

### 一、先验证目标是否存在

#### 1. 节点/路径类入口

优先检查：

- `/dev/...`
- `/proc/...`
- `/sys/...`
- `/proc/net/...`
- `/dev/video*`

常用检查：

```bash
adb shell ls -lZ /dev/<node>
adb shell ls -lZ /proc/<path>
adb shell ls -lZ /sys/<path>
```

需要记录：

- mode
- uid/gid
- SELinux type
- 路径是否存在

#### 2. 服务/组件类入口

优先检查：

- Binder service 是否存在
- exported Activity/Service/Receiver/Provider 是否存在
- socket/unix domain server 是否存在

常用检查：

```bash
adb shell service list
adb shell dumpsys package <package>
adb shell cmd package resolve-activity --brief <package>
```

#### 3. netlink / 协议入口

优先确认：

- 协议号是否在目标内核里存在
- family 名是否能枚举到
- 是否有对应内核模块/驱动启用

### 二、shell 身份验证

#### 1. 路径类最小验证

对 `/dev`、`/proc`、`/sys` 优先做最小动作：

- `stat`
- `open(O_RDONLY)`
- `open(O_WRONLY)`
- `open(O_RDWR)`
- 如果open成功，那么验证`read/write/ioctl/mmap`的是否可行

原则：

- 先做不会破坏系统状态的读/打开测试
- 写入或 ioctl 只做最小、安全、可回滚的探测
- 不清楚副作用时，不要盲目发送复杂 payload

#### 2. netlink 最小验证

优先做：

- `socket(AF_NETLINK, ...)`
- `bind()`
- 如有明确 family/cmd，再做最小注册或空消息测试

#### 3. binder / exported 组件最小验证

优先做：

- 枚举 service
- 最小 transact / am start / content query
- 看是否直接被权限拒绝

shell 验证后的结论应至少区分：

- shell 可见但不可 open
- shell 可 open 但不可写/不可 ioctl
- shell 可完成最小交互

### 三、普通 app 身份验证

这是重点。

#### 1. 验证方式选择

优先顺序：

1. Android Studio /Devecho Studio 工程 + JNI 探测器
2. 已存在测试 app 中加入最小 native/Java 代码
3. 仅当入口是纯组件级（如 exported activity/provider）时，可只用 Java/Kotlin

如果是 `/dev`、`/proc`、`ioctl`、`mmap`、`netlink` 之类，优先 JNI。

#### 2. app 里推荐测试动作

对每个候选入口，按最小可达性探测：

- `stat(path)`
- `open(path, O_RDONLY)`
- `open(path, O_WRONLY)`
- `open(path, O_RDWR)`
- 如果open成功，那么验证`read/write/ioctl/mmap`的是否可行：
  - `ioctl(fd, cmd, ...)`，重点注意：ioctl需要分析源码/二进制有哪些cmd，需要测试这些cmd是否有权限调用，返回值无`permission deny`.
  - `mmap()`
  - `socket(AF_NETLINK, ...)`
  - `bind()`
  - `connect()`


日志要求：

- 每一步都记日志
- 打印 errno
- 打印返回值
- 打印 uid/gid/pid
- 尽量写到 app 私有目录

#### 3. 与 app-jni-poc-verification 的协作

若使用 Android App / Harmony Hap 探测：

- 加载 `app-jni-poc-verification`
- JNI 入口只负责启动后台线程
- 真正探测逻辑放在线程里
- 用 `run-as <pkg> cat files/poc_trace.log` 取日志

### 四、最小 PoC 编写原则

这个 skill 写的是“reachability probe”，不是完整漏洞利用 PoC。

因此代码应满足：

- 每个入口单独测试或按类型分组测试
- 优先安全、只读、最小副作用
- ioctl 需要从源码/二进制中获取到所有cmd及参数，测试哪些cmd能访问
- mmap 只验证是否能映射，不先做危险读写
- netlink 先验证 socket/bind，再考虑最小消息
- Binder/组件只验证调用是否被权限拦截

### 五、输出归类标准

最终对每个入口按以下标准归类：

#### A. App 可达
满足：

- 普通 app 身份下可以 `stat/open/socket/bind/start/query/ioctl/mmap` 成功
- 或至少能进入目标服务/组件的最小处理路径

#### B. Shell 可达但 app 不可达
满足：

- adb shell 能成功访问
- 普通 app 明确返回 `EACCES/EPERM/SELinux denied` 或组件权限拒绝

#### C. 仅 system/特权可达
满足：

- shell 和普通 app 都失败
- 从权限/属组/签名权限/SELinux 可判断仅 system、media、camera、audio、system_app 等特权域可访问

#### D. 不可达或不存在
满足：

- 节点不存在、服务不存在、模块未加载
- 或没有任何低权限上下文可进入

### 六、必须明确区分的几件事

不要混淆：

- 源码里存在入口
- 设备上存在入口
- shell 可达
- 普通 app 可达
- 真的能到危险 handler

很多入口会出现：

- shell `ls -l` 能看到，但 app `stat()` 都被拒绝
- mode 很宽，但 SELinux 直接拦截
- exported 组件存在，但需要 signature 权限
- socket 可创建，但 bind/sendmsg 被拒绝

## 推荐执行顺序

1. 整理候选入口清单
2. 设备上检查存在性和权限
3. shell 做最小 reachability probe
4. 普通 app 做最小 reachability probe
5. 按 app/shell/system/不存在 分类
6. 输出结论与后续建议

## 输出要求

最终至少包含：

- 测试目标与设备信息
- 测试上下文：app / shell
- 测试方法
- 每个入口的验证结果
- 归类结论
- 若失败，写清失败点：
  - 节点不存在
  - DAC 拒绝
  - SELinux 拒绝
  - manifest/signature 权限拒绝
  - socket 创建失败
  - bind 失败
  - ioctl/mmap 失败

推荐表格：

| 入口 | 类型 | 设备存在 | shell可达 | app可达 | 失败点/限制 | 结论 |
|---|---|---|---|---|---|---|

## 最终结论模板

每个入口建议按这种格式写：

```text
- 入口：/dev/xxx
- 类型：char device / proc / netlink / binder / provider / activity
- 设备存在性：存在
- shell验证：open(O_RDONLY) 成功 / 失败
- app验证：stat() 失败，errno=13 (Permission denied)
- 限制：SELinux + DAC
- 结论：shell可达但普通app不可达
```

## 常见坑

- 只看 `ls -l` 权限，不做 app 实测
- shell 可达就误判为 app 可达
- 直接做危险 ioctl，而不是先做最小 reachability probe
- 没区分 `socket()` 成功和 `bind()/sendmsg()` 成功
- exported 组件存在就误判为任何 app 都能调
- 没有保留 errno、返回值、uid/gid，导致结论不可复核

## 与其他 skill 的配合

- 普通 app 探测：`app-jni-poc-verification`
- 先找入口再验证：`attack-entry-discovery`
