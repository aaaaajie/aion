# CyberChef 解题工具

AION 的 `system_cyberchef` 和 `tools/binaries/bin/cyberchef` 现在使用 Python 原生执行器。它保留 CyberChef 的 `operations`/`bake` JSON 协议、配方名称、任务产物和错误结构，但不再携带 Node、完整 CyberChef npm 包或网页运行时。CyberChef 代码只在 AION 镜像内发布，复用 Python 3.11；运行时禁止联网安装依赖。

## Agent 使用

先查询当前版本的操作和参数：

```json
{"action":"operations","query":"AES Decrypt"}
```

执行配方：

```json
{"input":"aGVsbG8=","recipe":[{"op":"From Base64"},{"op":"SHA2","args":{"size":"256"}}]}
```

`input_encoding=utf8|base64|hex` 只表示 CLI 传输层编码；`From Base64`、`From Hex` 等仍是配方步骤。`input_path` 只读取当前 Agent 工作区内的原始字节。查询不会启动任务，bake 通过现有 `system_task_output` 轮询任务结果。

## 第一版范围

操作清单由 `tools/cyberchef/engine.py` 单一注册表生成到 `tools/binaries/cyberchef/operations.json` 和 `operation-config.json`。范围包括：Base64/Base32/Base58/Hex/Binary/Charcode、URL/HTML Entity、ROT13/ROT47/Atbash/Vigenère/A1Z26/XOR、AES/AES Key Wrap、DES/3DES/RC2/RC4/RC4 Drop/Blowfish/ChaCha20/Salsa20/SM4、RSA/ECDSA、MD5/SHA-1/SHA-2/SHA-3/BLAKE2/RIPEMD、HMAC/CMAC/CRC、EVP/PBKDF2/HKDF/Scrypt/Bcrypt、PEM/DER/JWK/ASN.1/X.509 证书辅助以及 Gzip/Zlib/Raw Deflate。

OCR、图片、音视频、图表、HTML 渲染、网络请求、脚本、Magic、YARA、反汇编、PGP、GOST、RC6、Rabbit、XSalsa20、Argon2 和纯文本分析均不在第一版清单；直接执行时统一返回 `unsupported_operation`，不保留旧别名或兼容路径。

## CLI、限制与产物

```sh
printf '%s' '{"input":"aGVsbG8=","recipe":[{"op":"From Base64"}]}' \
  | tools/binaries/bin/cyberchef
tools/binaries/bin/cyberchef --job request.json --output-dir result
```

输入、每一步中间结果和最终输出均限制为 4 MiB，配方最多 32 步，超时为 1–120 秒。配方在独立 Python 进程中执行，超时会终止进程。默认结果用 `output_base64` 返回；指定 `--output-dir` 时生成权限为 0600 的 `result.bin` 和 `report.json`。所有最终结果都归一为字节，文本使用 UTF-8，哈希/签名/PEM 保持文本或原始字节的既定表示。

## 构建与离线依赖

`cryptography`、`bcrypt` 和固定版本 `PyCryptodome` 来自 `tools/binaries/offline-requirements.lock` 与离线 wheelhouse；`wheelhouse.sha256` 记录校验值。构建阶段先生成操作清单，再在 `--network=none` 下运行 CLI 回归。`deploy/Dockerfile.cyberchef` 不复制 Node 或 npm 资产；主工具链也不再声明 Node。

验证命令：

```sh
python scripts/build_cyberchef_python.py
python scripts/check_cyberchef_toolchain.py
```

CyberChef 专属发布内容只包含 Python 执行器、launcher、操作清单、许可证和 provenance；不生成独立 Node CyberChef tar 包。
