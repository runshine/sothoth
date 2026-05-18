---
name: app-jni-poc-verification
description: 当需要把 Android/Linux 内核漏洞 PoC 写进 Android Studio 或 DevEco Studio 工程，通过 JNI/Native 原生函数在 App 内运行，并使用 am start 拉起 Android 应用、通过 run-as 读取私有日志，或在 HarmonyOS 工程中编译/签名 HAP 包完成验证时使用本 skill。
---

# App 内 JNI PoC 验证

默认 Android 项目路径：`/Users/leitao/Desktop/AndroidStudioProjects/AppPoc`

如果是 HarmonyOS/DevEco Studio 工程，可使用：`/Users/leitao/Desktop/DevEcoStudioProjects/AppPoc`

把独立二进制 PoC 改写到 App 的 JNI/Native 路径里，适合以下场景：

- 设备不方便直接执行 `/data/local/tmp/poc_xxx`
- 需要以普通应用身份验证接口可达性
- 需要通过 `am start` 拉起 Android 应用
- 需要把阶段日志落到应用私有目录，再用 `run-as` 取回
- 需要在 HarmonyOS 工程里编译 HAP、配置签名并安装验证

## 工作流

### 1. 明确最小改造点

优先只改以下位置，不要先大改 App 结构：

- Java/Kotlin 入口：通常是 `MainActivity`
- JNI 导出函数：例如 `Java_com_example_xxx_MainActivity_stringFromJNI`
- 原生实现：通常在 `app/src/main/cpp/native-lib.cpp`

默认做法：

- `stringFromJNI()` 只负责启动后台线程并返回简短状态文本
- 真正的 PoC 放到独立的原生函数里执行
- 避免在 UI 线程直接跑 `open/ioctl/mmap` 链路

### 2. 日志优先落应用私有目录

不要优先把日志写到 `/sdcard`。优先用应用私有目录，例如：

```c
static const char *const kTraceFile =
    "/data/user/0/<package_name>/files/poc_trace.log";
```

理由：

- 避免外部存储/FUSE 干扰
- 普通应用通常可直接写自己的私有目录
- 可用 `run-as <package>` 稳定读取

日志要求：

- 每个关键步骤都打印
- 打印 `errno` 和关键信息
- 保留 `sizeof(struct xxx)`、设备节点、ioctl 返回值、映射地址、队列状态

### 3. JNI 推荐模式

推荐模式：

- JNI 入口只做一次性启动控制
- 使用 `pthread_create` 或等价线程 API
- 线程函数中执行 PoC
- 用原子变量防止重复启动

典型结构：

```c
static std::atomic<bool> g_started(false);

static void *RunPocThread(void *) {
    unlink(kTraceFile);
    (void)RunPoc();
    return nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_xxx_MainActivity_stringFromJNI(JNIEnv *env, jobject) {
    if (!g_started.exchange(true)) {
        pthread_t tid;
        if (pthread_create(&tid, nullptr, RunPocThread, nullptr) == 0) {
            pthread_detach(tid);
            return env->NewStringUTF("PoC thread started.");
        }
        g_started.store(false);
        return env->NewStringUTF("pthread_create failed.");
    }
    return env->NewStringUTF("PoC already started.");
}
```

### 4. 构建、签名与安装

优先使用工程原生构建，不再单独交叉编译 PoC 二进制。

#### 4.1 Android Studio / APK

常用命令：

```bash
cd /path/to/AndroidStudioProject
./gradlew assembleDebug
adb -s <serial> install -r /path/to/app-debug.apk
```

如果本机直接跑 `./gradlew` 提示 `Unable to locate a Java Runtime`，在 macOS 上优先尝试 Android Studio 自带 JBR：

```bash
export JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home'
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew assembleDebug
```

如果 JNI 只支持特定 ABI，检查 `app/build.gradle.kts` 里的 `ndk.abiFilters`。

#### 4.2 DevEco Studio / HarmonyOS HAP

先设置环境：

```bash
export DEVECO_SDK_HOME='/Applications/DevEco-Studio.app/Contents/sdk'
export JAVA_HOME='/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home'
export PATH='/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin:/Applications/DevEco-Studio.app/Contents/tools/ohpm/bin:'"$JAVA_HOME/bin:$PATH"
```

查看任务：

```bash
cd /path/to/DevEcoStudioProject
hvigorw tasks --no-daemon
```

编译 HAP：

```bash
hvigorw assembleApp -p product=default -p buildMode=debug --no-daemon
```

如果工程已在 `build-profile.json5` 中配置 `signingConfigs`，再次执行同一条 `assembleApp` 即可生成 signed HAP。

常见产物：

```bash
entry/build/default/outputs/default/entry-default-unsigned.hap
entry/build/default/outputs/default/entry-default-signed.hap
build/outputs/default/<project>-default-signed.app
```

如果 hvigor 报 `Invalid value of 'DEVECO_SDK_HOME'` 或 `SDK component missing`，优先检查：

- `DEVECO_SDK_HOME` 是否为 `/Applications/DevEco-Studio.app/Contents/sdk`
- DevEco Studio SDK 组件是否完整
- `JAVA_HOME` 是否指向 DevEco 自带 JBR


### 5. 拉起应用并取日志
常用启动方式：

```bash
hdc shell aa start -b <bundleName> -a <AbilityName>
```
查看应用与日志

```bash
hdc shell bm dump -n <bundleName>
hdc shell hilog | grep -i <bundleName>
```

如果需要确认应用是否已启动，也可结合：

```bash
hdc shell ps -A | grep <bundleName>
```



## 输出要求: 输入的漏洞是否为真实漏洞

最终至少给出：

- 是否真正触发漏洞；若失败，失败在什么检查点
- JNI 入口函数名


## 参考

- 需要完整命令清单、Android APK 工作流、HarmonyOS HAP 编译签名、以及鸿蒙安装/启动命令时，常见问题排查，再读 [references/android-app-jni-poc-workflow.md](references/android-app-jni-poc-workflow.md)
