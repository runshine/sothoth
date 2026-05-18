### 源码分析路径
#### 1. 内核/驱动/文件节点入口

重点搜这些模式：

- `struct file_operations` / `struct proc_ops`
- `.unlocked_ioctl` / `.compat_ioctl` / `.read` / `.write` / `.mmap` / `.open`
- `misc_register` / `register_chrdev` / `cdev_add` / `video_register_device`
- `proc_create*` / `proc_create_data*`
- `debugfs_create_*`
- `sysfs_create_*` / `DEVICE_ATTR` / `__ATTR`
- `SYSCALL_DEFINE*` / `COMPAT_SYSCALL_DEFINE*`
- `netlink_kernel_create` / `genl_register_family*`
- `setsockopt` / `getsockopt` handler
- 协议 handler 注册，如 `inet_add_protocol`
- binder/hwbinder/vndbinder service 注册点

对每个命中点继续看：

- 实际节点名或协议号，也就是外部调用中如何调用到这些命令或者函数，比如驱动的 ioctl cmd 需要先打开某个驱动 `/dev/xxx`
- 二进制/源码中有哪些命令可以访问，找出该节点、驱动、协议栈的所有命令

#### 2. 网络/协议栈入口

重点搜：

- socket 创建与监听点
- `accept` 后的命令分发
- 文本协议命令表
- TLV/消息结构解码函数
- 自定义 RPC handler
- 蓝牙/Wi‑Fi/NFC/USB 消息分发函数
- netfilter、netlink、rtnetlink、generic netlink family

优先找：

- 外部可控长度
- opcode/cmd 到 handler 的映射表
- 未鉴权命令
- 在解析前就分配/拷贝/索引的逻辑

最后输出用户态如何调用到这个 socket 的这个 cmd。