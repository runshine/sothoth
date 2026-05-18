---
name: huawei-secimg-boot-analysis
description: 分析和解包华为 secimg/HVB 风格 boot 镜像，识别证书链、密文主体和 HVB 元数据，并将各段提取到当前目录。
---

# 适用场景

当拿到一个名为 `boot.img` 的镜像，但它不是标准 Android boot image，文件头看起来像 DER/X.509 证书，怀疑是华为 secimg/HVB 安全镜像时使用。

典型特征：
- `file boot.img` 显示类似 `Certificate, Version=3`
- 开头字节是 ASN.1/DER（如 `30 82 ...`）
- 证书中出现 `Huawei Signature Center`、`secimg levelX cert`
- 证书扩展里出现 `boot`
- 镜像后半部分有 `HVB\0` 元数据

# 目标

1. 确认镜像不是标准 Android boot header
2. 识别证书链长度
3. 确认真实密文主体的起始偏移和长度
4. 提取：证书链、密文主体、HVB 元数据
5. 用哈希验证提取结果

# 操作步骤

假设目标文件为当前目录下的 `./boot.img`。

## 1) 初步识别格式

执行：

```bash
file ./boot.img
sha256sum ./boot.img
wc -c ./boot.img
python3 - <<'PY'
with open('boot.img','rb') as f:
    d=f.read(64)
print('magic16=', d[:16])
print('hex64=', d.hex())
PY
```

如果开头是 `30 82 ...`，优先按 DER/证书链处理，而不是按 Android boot.img 处理。

## 2) 解析前部证书链

先看 ASN.1：

```bash
openssl asn1parse -inform DER -in ./boot.img | head -n 180
```

并用脚本计算连续 DER 段长度：

```bash
python3 - <<'PY'
with open('boot.img','rb') as f:d=f.read(8192)

def der_total(buf, off):
    if off+2>len(buf) or buf[off]!=0x30:
        return None
    l=buf[off+1]
    if l < 0x80:
        return 2 + l
    n = l & 0x7f
    if off+2+n > len(buf):
        return None
    ln = int.from_bytes(buf[off+2:off+2+n], 'big')
    return 2 + n + ln

off=0
for i in range(5):
    ln=der_total(d,off)
    print('idx', i, 'off', off, 'len', ln)
    if not ln:
        break
    off += ln
PY
```

在当前样本中得到：
- cert0: offset 0, len 1954
- cert1: offset 1954, len 1484
- cert2: offset 3438, len 1842
- 证书链总长 = 5280 (`0x14a0`)

## 3) 确认密文主体起点

证书链后面可能还有对齐填充。用下面的方法找证书后的第一个非零字节：

```bash
python3 - <<'PY'
with open('boot.img','rb') as f:d=f.read(16384)
start=5280
n=0
while start+n < len(d) and d[start+n] == 0:
    n += 1
print('zero_pad_after_certs', n, hex(n))
print('first_nonzero_after_cert', hex(start+n), start+n)
PY
```

在当前样本中：
- 证书后零填充 = `0xb60`
- 真实载荷起点 = `0x2000`

## 4) 识别密文长度和 HVB 元数据

观察叶子证书的私有 OID 字段，重点关注：
- `2.20.2.65`：32 字节 SHA-256
- `2.20.2.67`：整数长度
- `2.20.2.69`：整数长度
- 还可能出现分区名 `boot`

当前样本中：
- `2.20.2.65` = `a9920d650dfbe74870f2b336fc0a709ad869020e160d27a63729765c88386d68`
- `2.20.2.67` = `33583104` = `0x2007000`
- `2.20.2.69` = `33583104` = `0x2007000`

因此推断：
- 密文主体起点：`0x2000`
- 密文主体长度：`0x2007000`
- 密文主体结束：`0x2009000`

再看 `0x2009000` 附近是否有 `HVB\0`：

```bash
python3 - <<'PY'
with open('boot.img','rb') as f:
    f.seek(0x2009000)
    d=f.read(256)
for i in range(0,256,16):
    chunk=d[i:i+16]
    hx=' '.join(f'{b:02x}' for b in chunk)
    asc=''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f'{0x2009000+i:08x}  {hx:<47}  {asc}')
PY
```

如果开头是 `48 56 42 00`，即 `HVB\0`，则说明这里是 HVB 元数据。

## 5) 提取到当前目录

按当前样本的已验证边界提取：

```bash
dd if=./boot.img of=./boot_certs.der bs=1 count=5280 2>/dev/null

dd if=./boot.img of=./boot_cipher.bin bs=1 skip=8192 count=33583104 2>/dev/null

dd if=./boot.img of=./boot_hvb.bin bs=1 skip=$((0x2009000)) count=$((0x7b0)) 2>/dev/null
```

## 6) 哈希验证

```bash
sha256sum ./boot_certs.der ./boot_cipher.bin ./boot_hvb.bin
```

当前样本已验证值：
- `boot_certs.der`: `4fbaa6af4b61542642743d45bdbd5eed777fb66590bcf94b22f52e1ff66634bd`
- `boot_cipher.bin`: `a9920d650dfbe74870f2b336fc0a709ad869020e160d27a63729765c88386d68`
- `boot_hvb.bin`: `1d9146819fcce4e73909047207c80b08c35f6114c62ee666139262dc1232df5e`

并且 `boot_cipher.bin` 的 SHA-256 应与叶子证书私有 OID `2.20.2.65` 一致。

# 结论判定

如果满足以下条件：
- 文件头为 DER/X.509 风格证书链
- 证书中出现华为 secimg levelX cert
- 证书私有字段绑定了 payload hash 和长度
- 主体数据高熵接近 8 bit/byte
- 尾部存在 `HVB\0`

则应判定该镜像为：
- 华为 secimg/HVB 安全镜像
- boot 分区内容已加密封装
- 不能仅靠通用解压算法还原内核明文

# 后续逆向方向：解密 boot_cipher.bin

## 已确认事实（基于实际分析）

### 启动链全加密
所有启动链镜像（xloader, bl2, fastboot, trustfirmware, teeos, hhee）的 payload 熵均为 ~7.95-7.96 bits/byte，全部加密。无法直接从固件包获取解密逻辑。

### 白盒 AES 实现
在 system.img（EROFS 格式）中发现 HarmonyOS 白盒 AES 库：

- `libwhiteboxaes.so`（~74KB，ELF aarch64）— 可从 EROFS 中的 ZIP/HAP 提取
- `libwb_aes.so`（~524KB）— 更大的实现库，可能跨 EROFS 块需要 erofs-utils 提取

核心 API：
```
wb_aes_ctx_new()          - 创建上下文
wb_aes_load_table(path)   - 加载白盒查找表
wb_aes_decrypt_gcm()      - AES-GCM 解密
wb_aes_encrypt_gcm()      - AES-GCM 加密
wb_aes_encrypt()          - 加密
wb_aes_cmc()              - AES-CMC 模式
wb_aes_ctx_release()      - 释放上下文
```

白盒表路径：`/data/storage/el2/base/files/table1.key`

### 加密模式
- 确认为 AES-GCM（基于 `gcm_decrypt`, `block_mul2`, `xor_block_128` 等 GHASH 组件）
- boot_cipher.bin 无重复 16 字节块，排除 ECB
- 文件大小 16 字节和 4096 字节对齐

### 证书 OID 字段不是直接密钥
已尝试所有 16 字节 OID 值（2.20.2.3/20/70/72）和 32 字节值（2.20.2.71）的 AES-ECB/CBC/GCM 组合，全部失败。这些字段是元数据参数，不是加密密钥。

## 从 EROFS 中提取 .so 文件的方法

当无法安装 erofs-utils 时，可直接在 EROFS 镜像中搜索 ZIP 本地文件头：

```python
import struct, zlib, mmap

path = 'system.img'
target_name = b'libwhiteboxaes.so'

with open(path, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    pos = 0
    while True:
        pos = mm.find(target_name, pos)
        if pos == -1:
            break
        # 向前搜索 PK\x03\x04 头
        search_start = max(0, pos - 256)
        chunk = mm[search_start:pos]
        pk_pos = chunk.rfind(b'PK\x03\x04')
        if pk_pos != -1:
            abs_pk = search_start + pk_pos
            hdr = mm[abs_pk:abs_pk+30]
            sig, ver, flags, method, mtime, mdate, crc, comp_size, uncomp_size, fname_len, extra_len = struct.unpack('<IHHHHHIIIHH', hdr)
            data_start = abs_pk + 30 + fname_len + extra_len
            comp_data = mm[data_start:data_start+comp_size]
            if method == 8:  # deflate
                data = zlib.decompress(comp_data, -15)
            elif method == 0:  # stored
                data = comp_data
            # 验证 ELF: data[:4] == b'\x7fELF'
        pos += 1
    mm.close()
```

注意：跨 EROFS 块的大文件可能解压失败（如 libwb_aes.so），此时需要 erofs-utils。

## 解密突破方向

1. **获取运行设备的白盒表**：从已 root 设备提取 `/data/storage/el2/base/files/table1.key`
2. **逆向 libwhiteboxaes.so**：用 IDA/Ghidra 分析白盒轮函数，尝试已知白盒 AES 攻击恢复标准密钥
3. **提取完整 libwb_aes.so**：安装 erofs-utils 挂载 system.img 提取
4. **分析 fw_dtb.img**：部分镜像签名但未加密（熵 3.30），设备树可能含 crypto engine 配置
5. **跨样本对比**：对比多版本固件的证书 OID 字段，区分固定参数和变化参数

## 核心障碍

密钥以白盒查找表形式存在，很可能与设备硬件绑定（eFuse/OTP）。仅从固件包无法完成解密。

# 注意事项

- 不要把这种镜像误判为标准 Android boot.img。
- 不要先花时间尝试大量解压算法；先确认是否为 secimg/HVB 安全封装。
- `strings` 中偶发出现的 `gzip`、`MZ` 等命中通常只是随机误命中，高熵密文中很常见。
- 起始偏移未必总是 `0x2000`；应优先通过 DER 长度、零填充、证书字段和 `HVB\0` 共同确认。
- `boot_hvb.bin` 大小在不同样本中可能不同，应依据 footer 和非零区边界核对。
