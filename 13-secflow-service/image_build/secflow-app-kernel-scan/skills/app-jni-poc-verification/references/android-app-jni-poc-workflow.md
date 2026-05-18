# Android App 内 JNI PoC 工作流参考

## 1. 推荐顺序

```bash
adb -s <serial> shell am force-stop <pkg>
adb -s <serial> shell run-as <pkg> rm -f files/poc_trace.log
cd /path/to/project
./gradlew assembleDebug
adb -s <serial> install -r /path/to/app-debug.apk
adb -s <serial> shell am start -n <pkg>/<activity>
adb -s <serial> shell run-as <pkg> cat files/poc_trace.log
```

## 2. 推荐日志内容

- 当前步骤名
- 设备节点名
- `errno`
- `sizeof(struct xxx)`
- 关键地址、长度、id、状态字段

## 3. 常用辅助命令

```bash
adb -s <serial> shell ps -A | grep <pkg>
adb -s <serial> shell pidof <pkg>
adb -s <serial> shell logcat -d | grep <tag>
adb -s <serial> shell uiautomator dump /data/local/tmp/ui.xml
adb -s <serial> shell cat /data/local/tmp/ui.xml
```

拉起应用：

```bash
adb -s <serial> shell am start -n <package_name>/<activity_name>
```

读取应用私有日志：

```bash
adb -s <serial> shell run-as <package_name> cat files/poc_trace.log
```

删除旧日志：

```bash
adb -s <serial> shell run-as <package_name> rm -f files/poc_trace.log
```

强停旧进程：

```bash
adb -s <serial> shell am force-stop <package_name>
```

## 4. 鸿蒙 HAP 编译与签名

如果测试工程是 DevEco Studio 的 HarmonyOS 工程，而不是 Android Studio APK 工程，优先使用 DevEco 自带 hvigor 与 SDK。

### 4.1 环境变量

```bash
export DEVECO_SDK_HOME='/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony'
export JAVA_HOME='/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home'
export PATH='/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin:/Applications/DevEco-Studio.app/Contents/tools/ohpm/bin:'"$JAVA_HOME/bin:$PATH"
```

说明：有些机器把 `DEVECO_SDK_HOME` 设为 `/Applications/DevEco-Studio.app/Contents/sdk` 会让 hvigor 继续报配置错误；优先使用具体 Harmony SDK 根目录 `.../sdk/default/openharmony`。

### 4.2 查看可用任务

```bash
cd /path/to/DevEcoStudioProject
hvigorw tasks --no-daemon
```

### 4.3 编译 HAP

```bash
cd /path/to/DevEcoStudioProject
hvigorw assembleApp -p product=default -p buildMode=debug --no-daemon
```

常见产物路径：

```bash
entry/build/default/outputs/default/entry-default-unsigned.hap
entry/build/default/outputs/default/app/entry-default.hap
build/outputs/default/<project>-default-unsigned.app
```

### 4.4 配置并生成签名包

在 `build-profile.json5` 中配置：

- `signingConfigs`
- `products[].signingConfig`
- `material.certpath`
- `material.storeFile`
- `material.profile`
- `material.keyAlias`
- `material.keyPassword`
- `material.storePassword`
- `material.signAlg`

再次执行：

```bash
hvigorw assembleApp -p product=default -p buildMode=debug --no-daemon
```

签名后常见产物路径：

```bash
entry/build/default/outputs/default/entry-default-signed.hap
build/outputs/default/<project>-default-signed.app
```

如果 hvigor 报 `Invalid value of 'DEVECO_SDK_HOME'` 或 `SDK component missing`，优先检查：

- `DEVECO_SDK_HOME` 是否指向 `/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony`
- DevEco Studio SDK 组件是否完整
- `JAVA_HOME` 是否指向 DevEco 自带 JBR
- 若构建仍失败，立即搜索工程内已有 `.hap` 历史产物，记录其路径、大小、SHA-256，并明确说明这些产物可能早于当前源码修改，不能误报成“刚刚重编成功”
- 在准备实机验证前，先执行 `hdc list targets`（必要时再看 `adb devices`）确认设备已连接，否则不要把失败原因误判成应用或签名问题

## 5. 鸿蒙 HAP 安装与启动

如果目标设备是 HarmonyOS，优先使用 `hdc` 安装和拉起应用。

### 5.1 查看设备

```bash
hdc list targets
```

### 5.2 安装 HAP

```bash
hdc install -r /path/to/entry-default-signed.hap
```

如果工程输出的是 `.app`，通常优先安装最终需要的 `.hap` 模块包；若设备和工程流程要求安装 `.app`，再按对应部署流程处理。

### 5.3 启动应用

先确认 bundleName 和 ability 名称，可从模块产物里的 `module.json` 或工程配置中读取，例如：

- bundleName: `com.example.apppoc`
- mainElement: `EntryAbility`

常用启动方式：

```bash
hdc shell aa start -b <bundleName> -a <AbilityName>
```

例如：

```bash
hdc shell aa start -b com.example.apppoc -a EntryAbility
```

### 5.4 查看应用与日志

```bash
hdc shell bm dump -n <bundleName>
hdc shell hilog | grep -i <bundleName>
```

如果需要确认应用是否已启动，也可结合：

```bash
hdc shell ps -A | grep <bundleName>
```

### 5.5 卸载应用

```bash
hdc uninstall <bundleName>
```

## 6. 判定原则

- 成功触发：看到明确的越界/UAF/崩溃/异常状态证据
- 路径触达但未触发：明确写出最后一个成功步骤和第一个失败步骤
- 不可达：明确写出权限、节点或 SELinux 阻断点

## 7. 辅助排查

必要时结合以下手段：

- `ps -A | grep <package_name>`：看进程是否为 `S/D` 状态
- `logcat | grep <tag>`：看 `__android_log_print` 输出
- `uiautomator dump`：确认当前界面文本是否已更新到新版本 APK
- `pm path <package_name>`：确认安装包状态

如果 `run-as` 可用，优先信任应用私有日志，不要只看 `logcat`。

## 常见问题

### 安装成功但界面还是旧文案

- 重新确认安装的 APK 路径
- 用 `uiautomator dump` 验证当前界面文本
- 必要时 `am force-stop` 后再 `am start`

### 线程无日志或进程卡死

- 先排除 `/sdcard` 日志路径问题，改为 `/data/user/0/<pkg>/files/...`
- 给每个阶段加日志，确认停在哪一步
- 把 JNI 入口和工作线程入口都写日志

### ioctl 链路失败

- 在应用私有日志里保留完整返回值
- 打印关键输入字段
- 若失败稳定复现，先把阻断点缩到具体 ioctl 或 mmap，而不是空泛地说“PoC 未触发”