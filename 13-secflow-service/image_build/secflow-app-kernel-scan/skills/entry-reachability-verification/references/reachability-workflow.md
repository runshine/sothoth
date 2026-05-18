# 攻击入口可达性验证工作流

## 1. 设备存在性检查

```bash
adb devices
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell id
```

### 路径类入口

```bash
adb shell ls -lZ /dev/<node>
adb shell ls -lZ /proc/<path>
adb shell ls -lZ /sys/<path>
```

### 服务/组件类入口

```bash
adb shell service list
adb shell dumpsys package <package>
adb shell cmd package resolve-activity --brief <package>
```

## 2. shell 身份最小验证

### /dev /proc /sys

```bash
adb shell 'cat /proc/<path>'
adb shell 'echo test > /proc/<path>'
adb shell 'toybox ls -l /dev/<node>'
```

如果需要真正的 open/ioctl/mmap，建议写最小 C 程序推到 `/data/local/tmp` 再执行。

## 3. 普通 app 身份最小验证

推荐配合 Android Studio 工程 + JNI：

```bash
adb shell am force-stop <pkg>
adb shell run-as <pkg> rm -f files/poc_trace.log
adb shell am start -n <pkg>/<activity>
adb shell run-as <pkg> cat files/poc_trace.log
```

JNI 里优先测试：

- `stat(path)`
- `open(path, O_RDONLY)`
- `open(path, O_WRONLY)`
- `open(path, O_RDWR)`
- `socket(AF_NETLINK, ...)`
- `bind()`
- `startActivity` / `query()` / `bindService`

## 4. 推荐结果分类

- app可达
- shell可达但app不可达
- 仅特权可达
- 不存在/不可达

## 5. 记录要点

每次都记录：

- uid/gid/pid
- 返回值
- errno
- 节点权限
- SELinux label
- 当前测试身份（shell/app）
