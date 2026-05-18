### 二进制分析路径

当没有源码或源码不完整时，使用反编译工具分析，按以下顺序做。对于“内核二进制、内核模块、驱动二进制”的入口识别，要比普通 ELF 逆向更细化，必须显式区分：

> **大体量 ELF 直接走子流程**：如果目标满足任一条件：
> - 文件 ≥ 50MB
> - `readelf -s | wc -l` ≥ 20000
> - 导出符号 ≥ 3000
> - 目标是 `vmlinux` / 巨型 `.so` / 大型 daemon
>
> **不要继续用本文件**，改走 `large-binary-attack-surface` skill，它用 manifest→预过滤→分批→回执→覆盖率校验的确定性流水线保证不漏扫。本文件仅适用于几十 KB 到几 MB 的常规二进制。



- 系统调用入口
- 字符/块设备入口
- procfs/sysfs/debugfs 入口
- netlink/generic netlink 入口
- 协议栈 handler 入口
- Binder/IPC/导出组件入口（若目标不是内核）

#### 1. 先做基础画像

使用字符串、符号、导入导出、节区信息判断目标类型：

- 可执行文件还是共享库
- 是否含符号
- 是否是 C++/Rust/Go 程序
- 是否是 `vmlinux`、`Image`、`bzImage`、`boot.img` 中解出的内核
- 是否是 `.ko` / vendor 内核模块

环境兼容性提示：

- 不要假设 `readelf` 一定存在；在 macOS 主机上经常只有 `objdump`、`nm`、`strings`，或 NDK 自带的 `llvm-readelf`
- 如果 `readelf` 不存在，优先回退到：
  1. `file <binary>` 确认架构/是否 stripped
  2. `nm -n <binary>` 枚举符号与地址
  3. `strings -a <binary>` 提取节点名、路径、协议名、日志串
  4. 若有 `llvm-readelf` / `objdump -h`，再补充节区信息
- 对于"带完整符号的 vmlinux.elf"，`nm + strings` 往往已经足够完成第一轮攻击面测绘；不要因为缺少 `readelf` 就中断分析
- **工作目录不稳定问题**：在长时间多步骤分析中，终端会话的 cwd 可能在调用之间被重置（尤其是 macOS + 云沙箱环境）。**最佳实践**：在脚本开头用一个变量保存二进制绝对路径（如 `VMLINUX="$(pwd)/vmlinux.elf"`），所有后续命令一律用绝对路径或在每条命令前加 `cd <dir> &&`，不要依赖 cwd 保持不变。第一次 `file` 成功后立即 `realpath` 并记录

重点关注字符串：

- `/dev/` `/proc/` `/sys/`
- `ioctl`，`mmap`, `release`, `close`, `open`, 命令字
- `binder` `service` `onTransact`
- `socket` `accept` `listen` `connect`
- `netlink` `genl`
- `cmd` `opcode` `request` `dispatch` `handle`
- URI、intent action、provider 路径、service name
- `unlocked_ioctl` `compat_ioctl` `mmap` `seq_read` `single_open`
- `sys_call_table` `__arm64_sys_` `__x64_sys_` `__se_sys_` `SyS_`
- `proc_create` `debugfs_create` `device_create` `misc_register` `cdev_add`

#### 2. 内核二进制里的驱动入口识别

这是重点。对 `vmlinux`、内核映像解包产物、`.ko` 模块，不要只看字符串，必须通过反编译工具按“handler函数 → ops 结构体 → 注册函数调用点”恢复驱动注册路径。

##### 2.1 字符/块设备入口恢复

恢复步骤：
1. 搜索驱动句柄函数：
   - `open`
   - `read`
   - `write`
   - `ioctl`
   - `mmap`
   - `poll`
   - `release`
2. 搜索交叉引用，分析ops结构体： `miscdevice` / `file_operations` / `block_device_operations` / `v4l2_file_operations`
3. 找注册函数调用点
   - `*dev_create`
   - `misc_register`
   - `__register_chrdev` / `register_chrdev`
   - `cdev_add`
   - `device_create`
   - `alloc_chrdev_region`
   - `blk_register_region` / `register_blkdev`
   - `video_register_device`
   - `anon_inode_getfd`
   - `*chrdev_create`

4. 同时提取节点名、minor、类名、device name

要特别注意：

- 在 stripped binary 中，`file_operations` 结构体经常无符号名，但可以通过“多个函数指针连续落在 rodata/data 段”的方式反推
- 如果某函数被大量 xref 作为结构体成员引用，且其原型像 `(struct file *, unsigned int, unsigned long)`，优先怀疑是 `ioctl`
- 若某函数原型像 `(struct file *, struct vm_area_struct *)`，优先怀疑是 `mmap`

##### 2.2 procfs / sysfs 入口恢复

ops注册点：
- `proc_create`
- `proc_create_data`
- `proc_create_seq_private`
- `debugfs_create_file`
- `debugfs_create_dir`
- `sysfs_create_file`
- `device_create_file`
- `kobject_create_and_add`
- `single_open` / `seq_read` / `seq_lseek` / `single_release`

恢复步骤：
1. 从路径字符串或节点名字符串入手
2. 找创建函数调用点
3. 回溯传入的 `proc_ops` / `file_operations` / `seq_operations` / `attribute_group`
4. 恢复对应 `proc_read` / `proc_write` / `show` / `store`
5. 判断是：
   - 纯只读信息暴露
   - 可写控制面
   - 调试接口
   - 复杂命令解析入口
6. 如果找不到，则反向查找，从5->1
特别注意：

- `show/store` 类 sysfs 入口常被忽略，但很多驱动漏洞就在 `store()` 里
- 只有 `show()` 的 debug 节点一般优先级低；带 `write/store` 的优先级高
- `seq_file` 链路要追完整：创建点 → open → show/read，不要只停在 `seq_read`

##### 2.3 netlink / generic netlink 入口恢复

优先找：

- `netlink_kernel_create`
- `genl_register_family`
- `genl_register_family_with_ops`
- `genlmsg_put`
- `nlmsg_put`
- `NETLINK_` 协议号字符串或常量
- family name 字符串

恢复步骤：

1. 定位协议号或 family name
2. 找创建/注册函数
3. 恢复 `input` callback 或 `genl_ops` 表
4. 恢复每个 cmd / op 对应 handler
5. 检查是否有：
   - `GENL_ADMIN_PERM`
   - `GENL_UNS_ADMIN_PERM`
   - `netlink_capable`
   - `ns_capable`
   - uid/pid 注册校验

特别注意：

- classic netlink 常见模式是“先注册 user_pid，再接收控制消息”，这种要找是否仅按 `nlmsg_pid` 认身份
- generic netlink 要把 family 级别和 op 级别权限分开判断

##### 2.4 协议栈 / socket 路径入口恢复

优先找：

- `inet_add_protocol`
- `proto_register`
- `setsockopt` / `getsockopt`
- `recvmsg` / `sendmsg`
- `packet_type`
- `net_protocol`
- `nf_register_net_hook`

恢复目标：

- 协议接收 handler
- sockopt handler
- packet handler
- netfilter hook 中用户可控数据首次进入的位置

#### 3. 从字符串回溯处理函数

常见方法：

- 用字符串交叉引用找到注册表和命令分发表
- 找 `switch(cmd)` / handler table / virtual dispatch
- 找 `open("/dev/..." )`、`property_get`、`ioctl`、`recv`、`read`
- 找消息解包函数，再向上回溯入口
- 对内核二进制，从节点名/协议名/设备名反推创建点和 ops 结构体

