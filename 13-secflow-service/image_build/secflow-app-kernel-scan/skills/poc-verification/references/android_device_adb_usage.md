# 安卓设备调试指南

## 推荐编译命令

```bash
aarch64-linux-android21-clang ./AI4EXP/poc_xxx.c -O0 -g -Wall -Wextra -o ./AI4EXP/poc_xxx
```

如果需要头文件搜索路径，再额外补 `-I`，不要先盲目复制整套内核头。

## 推荐推送与执行命令

```bash
adb push ./AI4EXP/poc_xxx /data/local/tmp/
adb shell chmod 755 /data/local/tmp/poc_xxx
adb shell /data/local/tmp/poc_xxx
```
## 获取内核日志
```bash
#获取调用栈
adb shell "cat /sys/fs/pstore/console-ramoops-0" 2>&1 | grep -A 30 "Call trace" | head -40

#获取内核日志
adb shell "cat /sys/fs/pstore/console-ramoops-0" 2>&1 | wc -l; adb shell "cat /sys/fs/pstore/console-ramoops-0" 2>&1 | grep -i "panic\|bug\|oops\|Unable to handle\|Internal error\|Call trace\|pc :\|lr :\|refcount\|sched_core\|core_prefer\|kmem_cache\|kfree\|use.after\|exception" 2>&1 | head -80
```
## 常见排错点

### 设备节点不存在

- 用 `adb shell ls -l /dev`
- 用 `adb shell find /dev -name '*关键字*' 2>/dev/null`
- 用 `adb shell ls -l /proc` 或 `adb shell ls -l /sys`

### 权限不够，检查权限

- 看节点权限和属组
- 看当前 shell 身份
- 必要时查看 `getenforce`

```bash
adb shell id
adb shell ls -l /dev/xxx
adb shell getenforce
```

### ioctl 编号不匹配

- 回到 UAPI 头文件确认 `_IO`、`_IOR`、`_IOW`、`_IOWR`
- 确认魔数、序号、结构体大小

### 结构体布局不匹配

- 优先使用固定宽度整数类型
- 必要时打印 `sizeof(struct xxx)`
- 核对内核与用户态的字段顺序

### 竞态漏洞不稳定

- 增加循环次数
- 增加线程并发
- 缩短用户态两步操作之间的间隔
- 保留阶段日志，确认实际进入了目标路径

## 最终结论模板

至少回答以下问题：

- 该漏洞是否被当前 PoC 成功触发
- 触发接口是什么
- 非 `root` 是否可达
- 观测现象是什么
- 若失败，失败在什么环节
