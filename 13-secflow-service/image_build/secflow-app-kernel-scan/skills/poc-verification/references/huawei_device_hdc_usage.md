# 华为设备调试指南

## hdc 推送运行方法
```bash
hdc file send poc /data/local/tmp
hdc shell chmod 755 /data/local/tmp/poc_xxx
hdc shell /data/local/tmp/poc
```

## 编译命令
```bash
aarch64-unkndow-
```

## 常见排查问题方法

1. 设备不存在
```bash
hdc list targets
```

2. 查看身份权限
```bash
hdc shell id
hdc shell getenforce
hdc shell ls -alZ /dev/xxx
```

3. 普通shell没权限查看设备/文件节点

直接把poc脚本写到app工程中，安装app去调试
```bash
//华为devecho工程目录：
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
- 若失败，阻塞点是路径不存在、权限不足、参数错误还是漏洞不可复现