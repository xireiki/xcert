# xcert

<p align="center">
  <img width="100px" src="icon.svg" alt="xcert" />
  <p align="center">用 Go 实现的 X.509 证书颁发工具</p>
  <p align="center"><a href="index.en.md">English</a> | 简体中文</p>
</p>

用 Go 实现的 X.509 证书颁发工具，用于生成自签根证书、中间证书和域名证书，并提供基于 SQLite 的证书数据库管理功能（列出、查询、删除、吊销、解除吊销、生成 CRL）。

密钥与证书操作全部使用 Go 标准库完成，不依赖外部命令。

> **免责声明**：本项目仅供内部管理与技术研究使用，未经任何安全审计，不保证其正确性、安全性或合规性。请勿在生产环境、公开信任体系或任何涉及真实业务的场景中使用本工具签发证书。使用者应自行评估并承担因使用本项目产生的一切风险与后果，作者不对由此造成的任何损失或法律责任负责。

## 目录

- [功能特性](#功能特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [命令总览](#命令总览)
- [全局选项与行为](#全局选项与行为)
  - [全局参数](#全局参数)
  - [主体信息格式](#主体信息格式)
  - [日志](#日志)
  - [退出码](#退出码)
- [root：创建根证书](#root创建根证书)
- [inte：创建中间证书](#inte创建中间证书)
- [cert：创建域名证书](#cert创建域名证书)
- [info：查看证书详情](#info查看证书详情)
- [db：管理证书数据库](#db管理证书数据库)
- [通用参数详解](#通用参数详解)
- [参考](#参考)
  - [密钥与文件格式](#密钥与文件格式)
  - [目录结构示例](#目录结构示例)
  - [数据库结构](#数据库结构)
  - [兼容旧的 xcert.sh 目录](#兼容旧的-xcertsh-目录)
  - [协议符合性](#协议符合性)
- [项目结构](#项目结构)
- [AI 开发规范](#ai-开发规范)
- [许可证](#许可证)

## 功能特性

- 生成根 CA（`root`）、中间 CA（`inte`）、域名证书（`cert`）
- 支持 ECC（prime256v1 / P-256）、RSA（不小于 2048 位）与 ed25519 私钥
- CA 数据保存到每个 CA 目录下的 SQLite 数据库 `xcert.db`
- 提供 `db` 子命令管理证书数据库
- 支持吊销证书并生成 X.509 CRL
- 可自定义密钥用法、扩展密钥用法、CA 路径长度、签名摘要算法、SKI/AKI 开关
- 默认使用随机序列号，也可切换为数据库递增序列号
- 分级日志与彩色输出

## 安装

要求 Go 1.27 或更高版本。

构建：

```sh
make build
```

或直接使用 Go 命令：

```sh
go build -o xcert ./cmd/xcert
```

安装到 `GOPATH/bin`：

```sh
make install
```

或直接从仓库安装：

```sh
go install github.com/xireiki/xcert/cmd/xcert@latest
```

运行测试：

```sh
make test
```

可用的 Makefile 目标：`all`（默认）、`build`、`race`、`test`、`vet`、`fmt`、`install`、`clean`。

## 快速开始

创建一个完整的证书链（根 CA、中间 CA、域名证书）：

```sh
xcert root -D ./ca
xcert inte -D ./ca -c ./ca/RootCA.cer -k ./ca/RootCA.key
xcert cert -D ./ca -d example.com -d www.example.com
```

生成结果位于 `./ca`，证书数据库为 `./ca/xcert.db`。

查看已签发的证书：

```sh
xcert db list -D ./ca
xcert db show example.com -D ./ca
xcert info -f ./ca/certs/example.com_ecc/example.com.cer
```

吊销证书并生成 CRL：

```sh
xcert db revoke example.com -D ./ca
```

## 命令总览

调用格式：

```
xcert <子命令> [参数]
```

| 子命令 | 说明 |
| --- | --- |
| [`root`](#root创建根证书) | 创建根证书 |
| [`inte`](#inte创建中间证书) | 创建中间证书，需由根证书或上级 CA 签发 |
| [`cert`](#cert创建域名证书) | 创建域名证书，由中间证书签发 |
| [`info`](#info查看证书详情) | 查看证书文件详情 |
| [`db`](#db管理证书数据库) | 管理证书数据库 |
| `help` | 显示帮助信息 |

直接执行 `xcert` 不带子命令时会输出错误并提示查看帮助；未知子命令同样会报错并提示查看帮助。

`xcert help` 显示总帮助，`xcert <子命令> --help` 显示对应子命令的完整参数与默认值。帮助内容由 cobra 依据子命令说明与参数定义生成。

行为约定：

- `root`、`inte` 与 `cert` 子命令在不带任何参数执行时会直接输出该子命令的帮助信息，而不会执行操作。只要指定了任意参数（含任意选项），即按参数执行。
- `info` 子命令不带 `-f` / `--file` 时会报错。
- `db` 子命令不带参数执行时显示其帮助信息；其子命令中需要参数的（如 `show`、`delete`、`revoke`）缺少参数时会报错。

## 全局选项与行为

### 全局参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--log-level` | `info` | 日志等级，可选 `trace`、`debug`、`info`、`warn`、`error`、`fatal`、`panic`，也可写作 `warning` |
| `--legacy` | `false` | 读取旧的 `xcert.sh` 目录（`serial`、`index.txt`），详见[兼容旧的 xcert.sh 目录](#兼容旧的-xcertsh-目录) |

这些参数可放在任意子命令之前或之后。

### 主体信息格式

`-s` / `--subject` 使用以斜杠分隔、形如 `/C=CN/O=Test SSL/CN=Test SSL CA` 的主体字符串。支持的字段键（大小写不敏感）：

| 键 | 含义 |
| --- | --- |
| `C` | 国家（Country） |
| `ST` 或 `S` | 省 / 州（State or Province） |
| `L` | 城市 / 地区（Locality） |
| `O` | 组织（Organization） |
| `OU` | 组织单位（Organizational Unit） |
| `CN` | 通用名称（Common Name） |
| `emailAddress` 或 `E` | 电子邮件地址 |

`C`、`ST`、`L`、`O`、`OU` 可重复出现并会累积为多值；`CN` 每次出现都会覆盖之前的值，`emailAddress` 可重复出现并累积为多值。空字段会被忽略；缺少 `=` 的片段会报错，不再被静默丢弃。

### 日志

日志等级由低到高为 `panic`、`fatal`、`error`、`warn`、`info`、`debug`、`trace`。默认等级为 `info`，即只输出不低于 `info` 的日志；设置为更高等级（如 `debug` 或 `trace`）会输出更详细的日志，设置为更低等级（如 `error`）会抑制 `info` 与 `warn`。

日志统一输出到标准错误。日志标签固定为等级的大写英文：

| 等级 | 标签 |
| --- | --- |
| `panic` | `PANIC` |
| `fatal` | `FATAL` |
| `error` | `ERROR` |
| `warn` | `WARN` |
| `info` | `INFO` |
| `debug` | `DEBUG` |
| `trace` | `TRACE` |

当标准错误是终端且未设置环境变量 `NO_COLOR` 时标签带颜色：`ERROR`、`FATAL`、`PANIC` 为红色，`WARN` 为黄色，`INFO` 为青色，`DEBUG`、`TRACE` 为白色。其他情况下输出纯文本。

命令产生的数据（如 `db list`、`db show` 的结果）输出到标准输出，与日志分离，便于重定向。

### 退出码

- `0`：执行成功
- `1`：参数错误、文件缺失、证书已存在之外的处理失败等

## root：创建根证书

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-C`, `--cipher` | `ecc` | 私钥类型，可选 `ecc`、`rsa` 或 `ed25519`。其他取值会报错 |
| `--rsa-bits` | `3072` | 生成 RSA 私钥时的位数，仅在 `--cipher rsa` 时生效，最小 2048 |
| `-s`, `--subject` | `/C=CN/O=Test SSL/CN=Test SSL CA` | 证书主体信息 |
| `--days` | `3650` | 证书有效期，单位为天，必须为正数 |
| `-D`, `--dir` | `.` | 文件保存目录 |
| `--key-usage` | `keyCertSign,cRLSign` | 密钥用法扩展，逗号分隔，多个值取并集 |
| `--ext-key-usage` | 空 | 扩展密钥用法，逗号分隔 |
| `--path-length` | `-1` | CA 路径长度限制，`-1` 表示不设置该限制 |
| `--digest` | `sha512` | 签名摘要算法，可选 `sha256`、`sha384`、`sha512` |
| `--subject-key-id` | `true` | 是否包含主体密钥标识符（SKI） |
| `--authority-key-id` | `true` | 是否包含颁发者密钥标识符（AKI）。根证书为自签，默认不会附带 AKI，该参数对根证书无实际作用 |
| `-h`, `--help` | | 显示帮助 |

`--key-usage`、`--ext-key-usage`、`--path-length`、`--digest`、`--subject-key-id`、`--authority-key-id` 的取值与语义详见[通用参数详解](#通用参数详解)。

### 行为

- 若目标目录下已存在 `RootCA.cer`，输出已存在的警告并直接返回，不覆盖。
- 创建目录及 `<dir>/newcerts`、`<dir>/crl`。
- 若 `<dir>/RootCA.key` 不存在，则按 `--cipher` 生成私钥。
- 生成自签根证书 `RootCA.cer`，签名摘要算法由 `--digest` 决定。
- 将根证书记录写入 `<dir>/xcert.db`，类型为 `root`，名称为 `RootCA`。
- 根证书使用随机序列号（128 位）。

根证书默认包含 `keyUsage`（`keyCertSign,cRLSign`）与 `basicConstraints`（`CA:TRUE`），并默认包含 SKI。

### 输出文件

| 文件 | 说明 |
| --- | --- |
| `RootCA.key` | 私钥，权限 0600 |
| `RootCA.cer` | 自签根证书 |
| `xcert.db` | 证书数据库 |
| `newcerts/` | 预留目录 |
| `crl/` | CRL 输出目录 |

## inte：创建中间证书

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-C`, `--cipher` | `ecc` | 私钥类型，可选 `ecc`、`rsa` 或 `ed25519` |
| `--rsa-bits` | `3072` | 生成 RSA 私钥时的位数，最小 2048 |
| `-s`, `--subject` | `/C=CN/O=Test SSL/CN=Test Inte CA` | 证书主体信息 |
| `--days` | `1825` | 证书有效期，单位为天，必须为正数 |
| `-D`, `--dir` | `.` | 文件保存目录 |
| `-c`, `--cert` | 无，必填 | 签发中间证书的上级 CA 证书路径 |
| `-k`, `--key` | 无，必填 | 签发中间证书的上级 CA 私钥路径 |
| `--sequential-serial` | `false` | 使用数据库递增计数器作为序列号；默认使用随机序列号 |
| `--key-usage` | `keyCertSign,cRLSign` | 密钥用法扩展 |
| `--ext-key-usage` | 空 | 扩展密钥用法 |
| `--path-length` | `0` | CA 路径长度限制，`-1` 表示不设置 |
| `--digest` | `sha512` | 签名摘要算法 |
| `--subject-key-id` | `true` | 是否包含 SKI |
| `--authority-key-id` | `true` | 是否包含 AKI |
| `-h`, `--help` | | 显示帮助 |

`--key-usage`、`--ext-key-usage`、`--path-length`、`--digest`、`--subject-key-id`、`--authority-key-id` 的取值与语义详见[通用参数详解](#通用参数详解)。

### 行为

- 若目标目录下已存在 `InteCA.cer`，输出已存在的警告并直接返回，不覆盖。
- `-c` 与 `-k` 为必填项，缺失或文件不存在时报错。
- 上级 CA 证书必须为 CA 证书且允许证书签名，否则报错。
- 创建目录及 `<dir>/newcerts`、`<dir>/crl`、`<dir>/certs`。
- 若 `<dir>/InteCA.key` 不存在，则按 `--cipher` 生成私钥。
- 生成证书请求 `InteCA.csr`（若不存在）。
- 使用上级 CA 证书与私钥签发 `InteCA.cer`。
- 生成证书链 `chain.cer`，内容为 `InteCA.cer` 与上级 CA 证书的拼接。
- 将中间证书记录写入数据库，类型为 `inte`，名称为 `InteCA`。
- 证书 `NotAfter` 取请求天数与上级 CA 的 `NotAfter` 中的较小值，保证不超过签发者有效期。
- 若上级 CA 不带 SKI，则不附带 AKI。

默认使用随机序列号；使用 `--sequential-serial` 时改为从数据库计数器读取并递增。

### 输出文件

| 文件 | 说明 |
| --- | --- |
| `InteCA.key` | 私钥，权限 0600 |
| `InteCA.csr` | 证书请求 |
| `InteCA.cer` | 中间证书 |
| `chain.cer` | 中间证书与上级 CA 证书拼接的证书链 |
| `xcert.db` | 证书数据库 |
| `certs/` | 域名证书目录 |
| `newcerts/`, `crl/` | 预留目录 |

## cert：创建域名证书

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-C`, `--cipher` | `ecc` | 私钥类型，可选 `ecc`、`rsa` 或 `ed25519` |
| `--rsa-bits` | `3072` | 生成 RSA 私钥时的位数，最小 2048 |
| `-s`, `--subject` | `/C=CN` | 证书主体信息 |
| `--days` | `90` | 证书有效期，单位为天，必须为正数；`--code-signing` 且未显式指定时默认 `365` |
| `-D`, `--dir` | `.` | CA 目录，用于定位数据库、CA 证书、CA 私钥与证书链 |
| `-c`, `--cert` | `<dir>/InteCA.cer` | 签发证书所用的 CA 证书 |
| `-k`, `--key` | `<dir>/InteCA.key` | 签发证书所用的 CA 私钥 |
| `--chain` | `<dir>/chain.cer` | 用于拼接 `fullchain.cer`（普通证书）或 `.pfx`（代码签名证书）的证书链 |
| `--ext-key-usage` | `serverAuth,clientAuth` | 扩展密钥用法，逗号分隔；为空则不写入该扩展 |
| `--code-signing` | `false` | 生成 Windows 代码签名证书；启用时扩展密钥用法固定为 `codeSigning`，且与 `--ext-key-usage` 互斥 |
| `--pfx-password` | 空 | 生成的 `.pfx` 文件密码，仅 `--code-signing` 时使用 |
| `-d`, `--domain` | 无 | 域名，可重复指定 |
| `--csr` | 无 | 签署外部证书请求，使用请求中的公钥与主体，不再生成私钥与请求 |
| `--sequential-serial` | `false` | 使用数据库递增计数器作为序列号；默认使用随机序列号 |
| `-h`, `--help` | | 显示帮助 |

`--ext-key-usage` 的取值与语义详见[通用参数详解](#通用参数详解)。

### 名称与 SAN 规则

- 通用名称 `CN` 与 `subjectAltName` 始终写入，满足 RFC 6125 主机名校验要求。
- 若通过 `-d` 指定了至少一个域名，主体 `CN` 取第一个域名（覆盖 `--subject` 或证书请求中的 `CN`），`subjectAltName` 包含全部域名。
- 若未指定 `-d`，则取 `--subject` 中的 `CN` 作为域名并写入 `subjectAltName`。
- 若 `-d` 与 `--subject` 的 `CN` 都为空，报错。
- 通用名称会进行路径安全校验：为空、等于 `.` 或 `..`、包含路径分隔符或控制字符时拒绝，避免输出路径逃逸 CA 目录。

### 行为

- 计算通用名称 `CN`，确定输出目录 `<dir>/certs/<CN>_<cipher>`。
- 若目标产物已存在（普通证书为 `fullchain.cer`，代码签名证书为 `<CN>.pfx`），输出已存在的警告并直接返回。
- 若 `<CN>.key` 不存在，则按 `--cipher` 生成私钥；已存在的私钥类型与 `--cipher` 不一致时报错。
- 若 `<CN>.csr` 不存在，则生成证书请求，其中包含与证书一致的 `subjectAltName`；已存在的证书请求与当前主体或 `subjectAltName` 不一致时会重新生成。
- 使用 CA 证书与私钥签发 `<CN>.cer`。
- 用于签发的 CA 证书必须为 CA 证书且允许证书签名，否则报错。
- 普通证书生成 `<CN>` 的完整证书链 `fullchain.cer`，内容为 `<CN>.cer` 与 `--chain` 指定文件内容的拼接；若 `<CN>.cer` 已存在而 `fullchain.cer` 缺失，会直接重建。代码签名证书改为生成 `<CN>.pfx`（见下）。
- 将域名证书记录写入数据库，类型为 `cert`，名称为 `CN`。
- 证书 `NotAfter` 取请求天数与签发 CA 的 `NotAfter` 中的较小值，保证不超过签发者有效期。
- 若签发 CA 不带 SKI，则不附带 AKI。

密钥用法依据密钥类型自动确定：ECDSA 与 ed25519 私钥使用 `digitalSignature`；RSA 私钥使用 `digitalSignature,keyEncipherment`。扩展密钥用法由 `--ext-key-usage` 决定，默认为 `serverAuth,clientAuth`，`basicConstraints` 为 `CA:FALSE`。签名摘要算法固定为 SHA-256。

### 代码签名证书

`cert --code-signing` 生成用于签名 Windows 程序的叶证书：

- 扩展密钥用法固定为 `codeSigning`（1.3.6.1.5.5.7.3.3），密钥用法固定为 `digitalSignature`。
- 默认有效期改为 365 天；显式指定 `--days` 时以指定值为准。
- 与 `--ext-key-usage` 互斥，同时指定会报错；也不能与 `--csr` 一起使用。
- 仅用于签发叶证书；签发前会校验签发 CA 的扩展密钥用法：CA 未设置 EKU，或包含 `codeSigning` / `any` 时才允许，否则报错。
- 不生成 `fullchain.cer`，改为生成 PKCS#12 文件 `<CN>.pfx`，其中包含叶证书、对应私钥与 `--chain` 中的 CA 证书链，密码由 `--pfx-password` 指定（默认空密码）。PFX 使用 PBES2 + PBKDF2-HMAC-SHA-256 + AES-256-CBC 加密。

### 签署外部证书请求

通过 `--csr` 可以签署由他人提供的证书请求，流程如下：

- 解析请求文件并校验其签名，签名无效或格式错误时报错。
- 使用请求中的公钥与主体信息，不再生成本地私钥；`--cipher`、`--rsa-bits`、`--subject` 在该模式下不生效。
- `subjectAltName` 取请求中的域名与 `-d` 指定域名的并集，`-d` 的域名在前；`CN` 取并集的第一个域名。
- 通用名称取并集的第一个域名；若请求与 `-d` 都没有域名，则取请求主体中的 `CN`。
- 输出目录与本地生成时一致，为 `<dir>/certs/<CN>_<密钥类型>`，其中密钥类型根据请求的公钥自动判断（`ecc`、`rsa`、`ed25519`）。
- 该模式下只写入 `<CN>.cer`、外部请求副本 `<CN>.csr` 与 `fullchain.cer`，不写入 `<CN>.key`；数据库记录中的 `key_path` 为空。

### 输出文件

在 `<dir>/certs/<CN>_<cipher>/` 下：

| 文件 | 说明 |
| --- | --- |
| `<CN>.key` | 私钥，权限 0600；使用 `--csr` 时不生成 |
| `<CN>.csr` | 证书请求，包含与证书一致的 `subjectAltName`；使用 `--csr` 时为外部请求的副本 |
| `<CN>.cer` | 域名证书 |
| `fullchain.cer` | 域名证书与证书链拼接的完整链；`--code-signing` 时不生成 |
| `<CN>.pfx` | 代码签名证书的 PKCS#12 文件（仅 `--code-signing`），含叶证书、私钥与 CA 证书链，替代 `fullchain.cer` |

## info：查看证书详情

`xcert info -f <证书文件>` 读取指定证书文件并打印详细信息，不依赖数据库，根证书、中间证书与叶证书均适用。

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-f`, `--file` | 无（必填） | 要查看的证书文件 |
| `-h`, `--help` | | 显示帮助 |

### 输出字段

`File`、`Subject`、`Issuer`、`Serial`、`Version`、`NotBefore`、`NotAfter`、`IsCA`、`PathLength`（仅 CA）、`KeyUsage`、`ExtKeyUsage`、`DNSNames`、`PublicKey`、`Signature`、`SubjectKeyId`、`AuthorityKeyId`（存在时）与 `SHA256` 指纹。

## db：管理证书数据库

数据库文件固定为 CA 目录下的 `xcert.db`，通过持久参数 `-D` / `--dir` 指定 CA 目录，默认 `.`。该参数可放在子命令之前或之后。

### 子命令

| 子命令 | 说明 |
| --- | --- |
| `db list` | 列出数据库中的全部记录 |
| `db show <serial\|name>` | 按序列号或名称显示一条记录 |
| `db import <cert-file>` | 把已有的证书文件补录进数据库 |
| `db delete <serial\|name>` | 删除一条记录；已吊销记录需加 `--force`，删除后保留墓碑 |
| `db revoke <serial\|name>` | 将记录状态标记为已吊销并重新生成 CRL |
| `db unrevoke <serial\|name>` | 将记录状态恢复为有效并重新生成 CRL |

`<serial|name>` 支持十六进制序列号（大小写不敏感）或证书名称。若名称匹配到多条记录，会提示结果有歧义并要求改用序列号。

### db list 输出

按插入顺序输出表格，列为：

| 列 | 说明 |
| --- | --- |
| `SERIAL` | 序列号（十六进制，大写） |
| `TYPE` | 类型：`root`、`inte`、`cert` |
| `NAME` | 名称：`RootCA`、`InteCA` 或域名 |
| `STATUS` | 状态：`V` 有效、`R` 已吊销 |
| `NOT_AFTER` | 到期时间，RFC 3339 格式 |

### db show 输出

输出单条记录的全部字段：

| 字段 | 说明 |
| --- | --- |
| `Serial` | 序列号 |
| `Type` | 类型 |
| `Name` | 名称 |
| `Subject` | 主体 |
| `Status` | 状态 |
| `NotBefore` | 生效时间 |
| `NotAfter` | 到期时间 |
| `Cert` | 证书文件路径 |
| `Key` | 私钥文件路径 |
| `Created` | 记录创建时间 |
| `Revoked` | 吊销时间，未吊销时为空 |

### db import 参数

把一个已存在的证书文件补录进数据库，用于 `xcert.db` 丢失或损坏后恢复记录，或导入外部生成的证书。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--key` | 空 | 记录中保存的私钥路径，会规范化为绝对路径 |
| `--name` | 证书的 `CN` | 记录名称 |

`db import <cert-file>` 从证书中读取序列号、主体、`NotBefore`、`NotAfter` 并写入数据库，证书与私钥路径统一以绝对路径保存。记录类型按证书实际属性自动判定：非 CA 为 `cert`，CA 且自签为 `root`，其余为 `inte`，不接受手动覆盖。若该序列号已有记录则输出警告并跳过。导入前会验证证书签名：自签证书必须自签有效（且为 CA），其他证书必须能由数据库 `root`/`inte` 记录中已存在的签发 CA 验签通过，否则报错；因此导入顺序应为根证书、中间证书、叶证书。早期版本保存的相对 `cert_path` 仍按当前工作目录解析，旧库在更换目录后可能需要按绝对路径重新导入签发者 CA 才能恢复验签。

### db delete 参数

在 `-D` / `--dir` 之外，还支持：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--force` | `false` | 删除已吊销记录；删除后保留一条墓碑记录，使该序列号继续出现在 CRL 中 |

`db delete` 删除数据库记录；对于域名证书（`cert`），会一并删除对应的 `<CN>.cer`、`<CN>.key`、`<CN>.csr`、`<CN>.pfx` 与 `fullchain.cer`。是否删除文件以证书本身为准：加载后若为 CA 证书则不删除任何文件，只删除数据库行，因此 `root`、`inte` 记录不会丢失 CA 文件；若 `<CN>.cer` 已缺失而无法判定，则退回按记录类型处理，`cert` 记录仍会清理其私钥等文件。已吊销（`R`）的记录默认拒绝删除，需加 `--force`；加 `--force` 后记录被软删除，`db list` 不再显示，但其序列号仍保留在 CRL 中。

### revoke / unrevoke 参数

在 `-D` / `--dir` 之外，还支持以下参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--ca-cert` | `<dir>/InteCA.cer` | 用于签发 CRL 的 CA 证书 |
| `--ca-key` | `<dir>/InteCA.key` | 用于签发 CRL 的 CA 私钥 |
| `--crl` | `<dir>/crl/<CA 文件名>.crl` | CRL 输出路径 |
| `--digest` | `sha512` | CRL 签名摘要算法，可选 `sha256`、`sha384`、`sha512` |
| `--crl-days` | `30` | CRL 的 `nextUpdate` 相对于当前时间的天数，必须为正数 |

`revoke` 会先将匹配记录的状态更新为 `R` 并记录吊销时间，然后重新生成 CRL；`unrevoke` 会先将状态恢复为 `V` 并清除吊销时间，然后重新生成 CRL。若 CRL 生成失败，命令会报错并回滚状态修改，保持数据库与 CRL 一致。用于签发 CRL 的 CA 证书必须为 CA 证书且允许 CRL 签名，且其私钥必须与证书匹配。`root`、`inte` 记录不允许吊销或解除吊销：CRL 只收录域名证书，吊销 CA 记录会报错。

CRL 使用 `X509 CRL` PEM 格式，CRL 编号来自数据库 `meta` 表中的独立递增计数器，在签名前取号。CRL 内容包含数据库中所有状态为 `R` 的域名证书记录，包括已软删除的墓碑记录。

## 通用参数详解

`--key-usage`、`--path-length`、`--digest`、`--subject-key-id`、`--authority-key-id` 仅 `root` 与 `inte` 支持；`--ext-key-usage` 由 `root`、`inte` 与 `cert` 支持。

### --key-usage

逗号分隔的密钥用法名称，多个值取并集。可用取值：

| 取值 | 含义 |
| --- | --- |
| `digitalSignature` | 数字签名 |
| `nonRepudiation` / `contentCommitment` | 不可否认 / 内容承诺 |
| `keyEncipherment` | 密钥加密 |
| `dataEncipherment` | 数据加密 |
| `keyAgreement` | 密钥协商 |
| `keyCertSign` | 证书签名 |
| `cRLSign` / `crlSign` | CRL 签名 |
| `encipherOnly` | 仅加密 |
| `decipherOnly` | 仅解密 |

未识别的取值会报错。

### --ext-key-usage

逗号分隔的扩展密钥用法名称。可用取值：

| 取值 | 含义 |
| --- | --- |
| `serverAuth` | TLS 服务端认证 |
| `clientAuth` | TLS 客户端认证 |
| `codeSigning` | 代码签名 |
| `emailProtection` | 电子邮件保护 |
| `ipsecEndSystem` | IPsec 终端系统 |
| `ipsecTunnel` | IPsec 隧道 |
| `ipsecUser` | IPsec 用户 |
| `timeStamping` | 时间戳 |
| `ocspSigning` / `OCSPSigning` | OCSP 签名 |
| `any` / `anyExtendedKeyUsage` | 任意用途 |

未识别的取值会报错。

`cert` 的默认值为 `serverAuth,clientAuth`；传空值（如 `--ext-key-usage=`）时不写入该扩展。

### --path-length

CA 路径长度限制。取值 `-1` 表示不写入路径长度限制；`0` 表示只允许签发终端证书，不允许再签发下级 CA；大于 `0` 表示允许的下级 CA 层级数。

### --digest

签名摘要算法，可选 `sha256`、`sha384`、`sha512`。会根据密钥类型自动选择对应算法（RSA 使用 RSASSA-PKCS1-v1_5，ECC 使用 ECDSA）；ed25519 忽略该参数，始终使用 Ed25519。

### --subject-key-id 与 --authority-key-id

用于控制是否包含 SKI 与 AKI 扩展。

- 当 `--subject-key-id=true`（默认）时，SKI 由标准库按 RFC 7093 方法一生成（对 `subjectPublicKey` 做 SHA-256 并截取 160 位）。
- 当 `--subject-key-id=false` 时，工具改为手动编码 `basicConstraints` 扩展，并让标准库不将证书视为 CA 以跳过自动生成 SKI。生成的证书仍带有正确的 `CA:TRUE` 扩展，证书链可正常验证。
- 当 `--authority-key-id=true`（默认）时，AKI 由标准库从父证书的 SKI 派生。
- 当 `--authority-key-id=false` 时，工具在签发前清空父证书对象中的 SKI，使标准库无法派生出 AKI。

## 参考

### 密钥与文件格式

- ECC 私钥：secp256r1（prime256v1 / P-256），PEM 类型 `EC PRIVATE KEY`
- ed25519 私钥：PEM 类型 `PRIVATE KEY`（PKCS#8）
- RSA 私钥：PEM 类型 `RSA PRIVATE KEY`（PKCS#1）
- 证书：PEM 类型 `CERTIFICATE`
- 证书请求：PEM 类型 `CERTIFICATE REQUEST`
- CRL：PEM 类型 `X509 CRL`
- 私钥文件权限为 `0600`，其余文件权限为 `0644`

### 目录结构示例

执行 `xcert root -D ./ca`、`xcert inte -D ./ca -c ./ca/RootCA.cer -k ./ca/RootCA.key`、`xcert cert -D ./ca -d example.com -d www.example.com` 后，目录结构如下：

```
ca
├── RootCA.key                root CA 私钥
├── RootCA.cer                root CA 自签证书
├── InteCA.key                intermediate CA 私钥
├── InteCA.csr                intermediate CA 证书请求
├── InteCA.cer                intermediate CA 证书
├── chain.cer                 intermediate CA 与上级 CA 拼接的证书链
├── xcert.db                  证书数据库（SQLite）
├── certs
│   └── example.com_ecc       域名证书目录，命名规则 <CN>_<密钥类型>
│       ├── example.com.key   域名私钥
│       ├── example.com.csr   域名证书请求
│       ├── example.com.cer   域名证书
│       └── fullchain.cer     域名证书与证书链拼接的完整链（代码签名证书为 <CN>.pfx）
├── newcerts                  预留目录
└── crl                       CRL 目录
    └── InteCA.crl            intermediate CA 签发的 CRL
```

### 数据库结构

`xcert.db` 为 SQLite 数据库，包含以下表。

`meta` 表：

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `key` | TEXT | 主键，计数器名称，`serial` 或 `crl` |
| `value` | TEXT | 计数器当前值，十六进制 |

`certs` 表：

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `id` | INTEGER | 主键，自增 |
| `serial` | TEXT | 序列号，十六进制大写 |
| `subject` | TEXT | 主体 |
| `type` | TEXT | 类型：`root`、`inte`、`cert` |
| `name` | TEXT | 名称 |
| `status` | TEXT | 状态：`V` 或 `R` |
| `not_before` | TEXT | 生效时间，RFC 3339 |
| `not_after` | TEXT | 到期时间，RFC 3339 |
| `cert_path` | TEXT | 证书路径 |
| `key_path` | TEXT | 私钥路径 |
| `created_at` | TEXT | 记录创建时间，RFC 3339 |
| `revoked_at` | TEXT | 吊销时间，RFC 3339，未吊销为空 |
| `deleted` | INTEGER | 是否已软删除；`1` 表示墓碑记录，`db list`/`db show` 不显示，但吊销信息仍保留在 CRL 中 |

序列号默认使用 128 位随机数，不占用数据库计数器；使用 `--sequential-serial` 时读取 `serial` 计数器（初始为 `01`）并递增。`root` 始终使用随机序列号。CRL 编号使用独立的 `crl` 计数器。

### 兼容旧的 xcert.sh 目录

当加上全局参数 `--legacy` 且 `-D` 指向由旧 [`xcert.sh`](https://gist.github.com/xireiki/acb4b35c49538ccfdb98c014747edc74) 生成的 CA 目录时，工具会读取旧的文件结构与记录，以便继续签发新证书：

- 私钥：兼容旧版 OpenSSL 生成的 `EC PARAMETERS` + `EC PRIVATE KEY` 文件，以及 RSA 私钥。
- 记录：若目录中存在 `serial` 或 `index.txt`，会在首次打开时读取 `serial` 以续接 `--sequential-serial` 的计数器，并把 `index.txt` 中的已签发/已吊销记录导入 `xcert.db`。
- 该目录结构已弃用，读取时会输出 `WARN` 级别的弃用警告。

#### 导入方法（xcert.sh）

导入在首次打开数据库时自动完成，无需单独命令。在旧目录上执行任意命令并加上 `--legacy` 即可，例如：

```sh
xcert --legacy db list -D ./oldca
```

首次运行会在 `./oldca` 下创建 `xcert.db`，把 `serial` 写入 `meta.serial` 计数器、把 `index.txt` 中的记录写入 `certs` 表，并输出一条 `WARN` 级弃用警告。导入后记录已在 `xcert.db` 中，后续命令可去掉 `--legacy`：

```sh
xcert db list -D ./oldca
```

导入只发生一次（`certs` 表为空时），工具不会写回 `serial` 或 `index.txt`，新记录仍只写入 `xcert.db`。不加 `--legacy` 时，`serial` 与 `index.txt` 会被忽略。导入存在两个已知降级点：`index.txt` 无法区分类别，所有记录都按 `cert` 类型导入；记录没有原始生效时间，`not_before` 统一写为导入时刻。如果这会影响使用，可用 `db import` 重新补录具体证书。

### 协议符合性

证书生成逻辑依据以下规范设计：

- RFC 5280：证书有效期不超出签发者；`keyUsage` 与 `basicConstraints` 扩展；签发者密钥标识符（AKI）计算。
- RFC 6125：主机名始终通过 `subjectAltName` 表达，`CN` 与 `subjectAltName` 保持一致。
- RFC 5480：ECDSA 证书的 `keyUsage` 不含 `keyEncipherment`。
- CA/Browser Forum Baseline Requirements：服务器证书签名摘要使用 SHA-256；CA 证书包含 `keyCertSign`；RSA 密钥长度不小于 2048；序列号包含至少 64 位密码学安全随机数。
- 生成的证书 `NotBefore` 相对当前时间回拨 1 分钟，避免客户端时钟偏差导致证书被视为尚未生效。

## 项目结构

```
.
├── .github/          GitHub Actions
├── cmd/xcert/        命令行入口，每个子命令一个 cmd_*.go 文件
├── docs/             MkDocs 文档源文件
├── log/              日志等级与输出
├── option/           命令行参数结构体
├── pki/              密钥与证书操作
├── store/            SQLite 证书数据库
├── icon.svg          项目图标
├── mkdocs.yml        MkDocs 配置
├── requirements-docs.txt
├── Makefile
├── go.mod
├── LICENSE
├── README.md
└── README.en.md
```

`docs/` 基于 MkDocs（Material 主题）构建，`docs/index.md`、`docs/index.en.md` 分别为 `README.md`、`README.en.md` 的副本，修改 README 后需同步复制。本地预览与构建：

```sh
pip install -r requirements-docs.txt
mkdocs serve
mkdocs build
```

## AI 开发规范

本仓库允许使用 AI 助手参与开发。AI 产生的改动与人工改动遵循同一标准，并由维护者审查后合入；面向 AI 助手的行为约束见 `AGENTS.md`，本节仅从项目角度说明对 AI 相关贡献的要求。

### 提交与测试

- 提交前运行 `go vet ./...` 与 `go test ./...`，并实际执行相关命令自测，确认通过。
- 每次提交同步更新 `README.md`，保持其中记录的子命令、参数、默认值、文件布局与行为与代码一致。
- 提交信息采用约定式提交（Conventional Commits）：`<type>(<scope>): <description>`。

### 代码改动原则

- 以最小的改动完成功能，避免顺带重构无关代码。
- 改动不得引入性能降级，也不得破坏既有功能。
- 优先使用标准库与既有依赖，不为几行代码可解决的问题新增依赖。
- 不添加未被要求的抽象、配置项或「以后可能用到」的脚手架。
- 新增非平凡逻辑时保留一个可运行的校验（测试或自检）。

### 参数与目录约定

- 命令行参数统一采用 GNU kebab-case 长选项风格。
- CA 目录统一为 `-D` / `--dir`。
- 长选项使用连字符，例如 `--rsa-bits`、`--path-length`、`--digest`、`--sequential-serial`、`--crl-days`。
- 高频操作保留短选项，其余仅提供长选项。
- 目录职责：`cmd/xcert/` 为命令行入口（每个子命令一个 `cmd_*.go`）；`pki/` 为密钥与证书操作；`store/` 为 SQLite 数据库；`option/` 为参数结构体；`log/` 为日志等级与输出。
- 命令帮助由 cobra 依据 `Short` 与参数说明自动生成，不在代码中硬编码帮助文本。

## 许可证

本项目采用 MIT 许可证，详见 `LICENSE` 文件。
