# 攻击入口发现命令速查

## 1. 源码扫描常用模式

### 内核/驱动入口

```bash
rg -n "struct file_operations|struct proc_ops" <target>
rg -n "\.unlocked_ioctl\s*=|\.compat_ioctl\s*=|\.read\s*=|\.write\s*=|\.mmap\s*=|\.open\s*=" <target>
rg -n "misc_register|register_chrdev|cdev_add|video_register_device" <target>
rg -n "proc_create|proc_create_data|proc_create_seq|proc_create_net" <target>
rg -n "debugfs_create_|sysfs_create_|DEVICE_ATTR|__ATTR" <target>
rg -n "SYSCALL_DEFINE|COMPAT_SYSCALL_DEFINE" <target>
rg -n "netlink_kernel_create|genl_register_family|genl_register_family_with_ops" <target>
rg -n "setsockopt|getsockopt|inet_add_protocol" <target>
```

### Android / Framework / App 入口

```bash
rg -n "android:exported=|intent-filter|ContentProvider|BroadcastReceiver|Service|Activity" <target>
rg -n "onTransact|BinderService|Bn[A-Za-z_]+|Bp[A-Za-z_]+|I[A-Za-z_]+Service" <target>
rg -n "JNIEXPORT|Java_[A-Za-z0-9_]+" <target>
rg -n "LocalServerSocket|ServerSocket|accept\(|listen\(|socket\(" <target>
```

### 协议/命令分发入口

```bash
rg -n "switch\s*\(.*cmd|switch\s*\(.*opcode|dispatch|handle_request|process_cmd|on_message" <target>
rg -n "recv\(|recvfrom\(|read\(|ioctl\(|copy_from_user|get_user" <target>
rg -n "json|protobuf|flatbuffer|cbor|xml" <target>
```

## 2. 二进制分析常用命令

### 基础画像

```bash
file <bin>
strings -a <bin> | less
nm -C <bin> 2>/dev/null | less
objdump -T <bin> 2>/dev/null | less
readelf -a <bin> | less
otool -L <bin>        # macOS 上看动态库依赖
```

### 普通 ELF / 用户态二进制入口线索

```bash
strings -a <bin> | egrep "/dev/|/proc/|/sys/|binder|service|socket|netlink|ioctl|onTransact|Java_"
strings -a <bin> | egrep "cmd|opcode|request|dispatch|handle|uri|content://|am start|intent"
nm -C <bin> 2>/dev/null | egrep "Java_|JNI_OnLoad|onTransact|Bn|Bp|Stub|Proxy"
strings -a <bin> | egrep "binder|hwbinder|vndbinder|service list|/dev/binder"
strings -a <bin> | egrep "listen|accept|AF_UNIX|AF_INET|AF_NETLINK"
objdump -d <bin> | less
readelf -Ws <bin> | egrep "handle|dispatch|process|parse|decode|onMessage|onTransact"
```

### 内核二进制 / 内核模块入口线索

```bash
strings -a vmlinux | egrep "misc_register|register_chrdev|cdev_add|device_create|proc_create|debugfs_create|sysfs_create|netlink_kernel_create|genl_register_family"
strings -a vmlinux | egrep "unlocked_ioctl|compat_ioctl|seq_read|single_open|sys_call_table|__arm64_sys_|__x64_sys_|__se_sys_"
strings -a <module.ko> | egrep "/dev/|/proc/|/sys/|NETLINK_|ioctl|misc_register|proc_create|device_create"
readelf -Ws vmlinux | egrep "__arm64_sys_|__x64_sys_|__se_sys_|compat_sys_|sys_call_table"
readelf -Ws <module.ko> | egrep "misc_register|register_chrdev|cdev_add|proc_create|debugfs_create|netlink_kernel_create"
objdump -d vmlinux | less
objdump -d <module.ko> | less
```

macOS 上如果系统没有 `readelf`/`nm` 的 ELF 版本，优先使用 Android NDK 自带 LLVM 工具链，例如：

```bash
$HOME/Library/Android/sdk/ndk/30.0.14904198/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf -h vmlinux.elf
$HOME/Library/Android/sdk/ndk/30.0.14904198/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-nm -n vmlinux.elf | grep __arm64_sys_
$HOME/Library/Android/sdk/ndk/30.0.14904198/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-objdump -d vmlinux.elf | less
```

如果要在鸿蒙设备上继续验证，`hdc` 常见可执行路径是：

```bash
/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc
```

### 驱动入口恢复时优先关注的模式

```bash
readelf -Ws <module.ko> | egrep "file_operations|proc_ops|seq_operations|genl_ops|net_protocol|block_device_operations"
strings -a <module.ko> | egrep "/dev/|/proc/|/sys/|video[0-9]|misc|ioctl|mmap|poll"
```

### 系统调用恢复时优先关注的模式

```bash
readelf -Ws vmlinux | egrep "__arm64_sys_|__x64_sys_|__ia32_sys_|__se_sys_|__do_sys_|compat_sys_"
strings -a vmlinux | egrep "sys_call_table|el0_svc|el0_sync|do_el0_svc|invoke_syscall"
```

## 3. Android / 设备侧可达性验证

### 设备与系统信息

```bash
adb devices
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell id
adb shell ps -AZ | head
```

### 节点权限

```bash
adb shell ls -lZ /dev/<node>
adb shell ls -lZ /proc/<path>
adb shell ls -lZ /sys/<path>
adb shell ls -lZ /dev/video*
```

### 服务与组件

```bash
adb shell service list
adb shell cmd package resolve-activity --brief <package>
adb shell dumpsys package <package>
adb shell pm path <package>
```

### 普通 app 身份验证

推荐配合 `app-jni-poc-verification`：

```bash
adb shell am force-stop <pkg>
adb shell run-as <pkg> rm -f files/poc_trace.log
adb shell am start -n <pkg>/<activity>
adb shell run-as <pkg> cat files/poc_trace.log
```

### shell 身份快速验证

```bash
adb shell 'cat /proc/net/<node>'
adb shell 'echo test > /proc/net/<node>'
adb shell 'toybox nc -h' || true
adb shell 'cmd -l | head -50'
```

## 4. 结果判定模板

对每个入口至少判断：

1. 源码里是否存在
2. 设备上是否存在
3. shell 是否可达
4. 普通 app 是否可达
5. 是否有额外权限前提

可直接套用以下结论模板：

```text
- 入口：<name>
- 类型：<proc/dev/netlink/binder/socket/syscall/...>
- 位置：<file:line 或 binary symbol/offset>
- 触发方式：<open/ioctl/bind/transact/intent/...>
- 设备存在性：存在/不存在
- shell可达：是/否/待确认
- 普通app可达：是/否/待确认
- 限制条件：<SELinux/DAC/manifest/signature/system/capability>
- 后续建议：<继续审计/写PoC/低优先级/需设备侧验证>
```

## 5. 常见优先级建议

优先深挖：

- 普通 app 可达
- 网络对端未鉴权可达
- world-readable/world-writable 但 handler 很重
- netlink/generic netlink 缺少权限检查
- exported 组件进入 native 或内核接口

降低优先级：

- 只读 debugfs
- 仅 root/system 可达且无提权价值
- 编译期调试功能、量产机默认不存在
- 没有实际 handler 或仅打印状态
