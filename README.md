# xcert

用 Go 实现的 X.509 证书颁发工具，用于生成自签根证书、中间证书和域名证书，并提供基于 SQLite 的证书数据库管理功能（列出、查询、删除、吊销、解除吊销、生成 CRL）。

密钥与证书操作全部使用 Go 标准库完成，不依赖外部命令。

## 功能特性

- 生成根 CA（`root`）、中间 CA（`inte`）、域名证书（`cert`）
- 支持 ECC（prime256v1 / P-256）与 RSA（不小于 2048 位）私钥
- CA 数据保存到每个 CA 目录下的 SQLite 数据库 `xcert.db`
- 提供 `db` 子命令管理证书数据库
- 支持吊销证书并生成 X.509 CRL
- 可自定义密钥用法、扩展密钥用法、CA 路径长度、签名摘要算法、SKI/AKI 开关
- 默认使用随机序列号，也可切换为数据库递增序列号
- 分级日志与彩色输出

## 构建与安装

要求 Go 1.27 或更高版本。

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
```

吊销证书并生成 CRL：

```sh
xcert db revoke example.com -D ./ca
```

## 命令总览

```
xcert <子命令> [参数]
```

| 子命令 | 说明 |
| --- | --- |
| `root` | 创建根证书 |
| `inte` | 创建中间证书，需由根证书或上级 CA 签发 |
| `cert` | 创建域名证书，由中间证书签发 |
| `db` | 管理证书数据库 |
| `help` | 显示帮助信息 |

直接执行 `xcert` 不带子命令时会输出错误并提示查看帮助；未知子命令同样会报错并提示查看帮助。

`xcert help` 显示总帮助，`xcert <子命令> --help` 显示对应子命令的完整参数与默认值。帮助内容由 cobra 依据子命令说明与参数定义生成。

## 全局说明

### 全局参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--log-level` | `info` | 日志等级，可选 `trace`、`debug`、`info`、`warn`、`error`、`fatal`、`panic`，也可写作 `warning` |

该参数可放在任意子命令之前或之后。

### 帮助行为

- `root`、`inte` 与 `cert` 子命令在不带任何参数执行时会直接输出该子命令的帮助信息，而不会执行操作。只要指定了任意参数（含任意选项），即按参数执行。
- `db` 子命令不带参数执行时显示其帮助信息；其子命令中需要参数的（如 `show`、`delete`、`revoke`）缺少参数时会报错。

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

`C`、`ST`、`L`、`O`、`OU` 可重复出现并会累积为多值；`CN` 与 `emailAddress` 每次出现都会覆盖之前的值，因此最终取最后一次出现的结果。空字段会被忽略。

## root：创建根证书

### 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-C`, `--cipher` | `ecc` | 私钥类型，可选 `ecc` 或 `rsa`。其他取值会报错 |
| `--rsa-bits` | `3072` | 生成 RSA 私钥时的位数，仅在 `--cipher rsa` 时生效，最小 2048 |
| `-s`, `--subject` | `/C=CN/O=Test SSL/CN=Test SSL CA` | 证书主体信息 |
| `--days` | `3650` | 证书有效期，单位为天 |
| `-D`, `--dir` | `.` | 文件保存目录 |
| `--key-usage` | `keyCertSign,cRLSign` | 密钥用法扩展，逗号分隔，多个值取并集 |
| `--ext-key-usage` | 空 | 扩展密钥用法，逗号分隔 |
| `--path-length` | `-1` | CA 路径长度限制，`-1` 表示不设置该限制 |
| `--digest` | `sha512` | 签名摘要算法，可选 `sha256`、`sha384`、`sha512` |
| `--subject-key-id` | `true` | 是否包含主体密钥标识符（SKI） |
| `--authority-key-id` | `true` | 是否包含颁发者密钥标识符（AKI）。根证书为自签，默认不会附带 AKI，该参数对根证书无实际作用 |
| `-h`, `--help` | | 显示帮助 |

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
| `-C`, `--cipher` | `ecc` | 私钥类型，可选 `ecc` 或 `rsa` |
| `--rsa-bits` | `3072` | 生成 RSA 私钥时的位数，最小 2048 |
| `-s`, `--subject` | `/C=CN/O=Test SSL/CN=Test Inte CA` | 证书主体信息 |
| `--days` | `1825` | 证书有效期，单位为天 |
| `-D`, `--dir` | `.` | 文件保存目录 |
| `-c`, `--cert` | 无，必填 | 签发中间证书的上级 CA 证书路径 |
| `-k`, `--key` | 无，必填 | 签发中间证书的上级 CA 私钥路径 |
| `--sequential-serial` | `false` | 使用数据库递增计数器作为序列号；默认使用随机序列号 |
| `--key-usage` | `keyCertSign,cRLSign` | 密钥用法扩展 |
| `--ext-key-usage` | `serverAuth,clientAuth` | 扩展密钥用法 |
| `--path-length` | `0` | CA 路径长度限制，`-1` 表示不设置 |
| `--digest` | `sha512` | 签名摘要算法 |
| `--subject-key-id` | `true` | 是否包含 SKI |
| `--authority-key-id` | `true` | 是否包含 AKI |
| `-h`, `--help` | | 显示帮助 |

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
- 若上级 CA 不带 SKI，则使用其公钥的 SHA-1 摘要作为 AKI。

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
| `-C`, `--cipher` | `ecc` | 私钥类型，可选 `ecc` 或 `rsa` |
| `--rsa-bits` | `3072` | 生成 RSA 私钥时的位数，最小 2048 |
| `-s`, `--subject` | `/C=CN` | 证书主体信息 |
| `--days` | `90` | 证书有效期，单位为天 |
| `-D`, `--dir` | `.` | CA 目录，用于定位数据库、CA 证书、CA 私钥与证书链 |
| `-c`, `--cert` | `<dir>/InteCA.cer` | 签发证书所用的 CA 证书 |
| `-k`, `--key` | `<dir>/InteCA.key` | 签发证书所用的 CA 私钥 |
| `--chain` | `<dir>/chain.cer` | 用于拼接 `fullchain.cer` 的证书链 |
| `-d`, `--domain` | 无 | 域名，可重复指定 |
| `--csr` | 无 | 签署外部证书请求，使用请求中的公钥与主体，不再生成私钥与请求 |
| `--sequential-serial` | `false` | 使用数据库递增计数器作为序列号；默认使用随机序列号 |
| `-h`, `--help` | | 显示帮助 |

### 名称与 SAN 规则

- 通用名称 `CN` 与 `subjectAltName` 始终写入，满足 RFC 6125 主机名校验要求。
- 若通过 `-d` 指定了至少一个域名，主体 `CN` 取第一个域名（覆盖 `--subject` 或证书请求中的 `CN`），`subjectAltName` 包含全部域名。
- 若未指定 `-d`，则取 `--subject` 中的 `CN` 作为域名并写入 `subjectAltName`。
- 若 `-d` 与 `--subject` 的 `CN` 都为空，报错。
- 通用名称会进行路径安全校验：为空、等于 `.` 或 `..`、包含路径分隔符或控制字符时拒绝，避免输出路径逃逸 CA 目录。

### 行为

- 计算通用名称 `CN`，确定输出目录 `<dir>/certs/<CN>_<cipher>`。
- 若该目录下已存在 `fullchain.cer`，输出已存在的警告并直接返回。
- 若 `<CN>.key` 不存在，则按 `--cipher` 生成私钥；已存在的私钥类型与 `--cipher` 不一致时报错。
- 若 `<CN>.csr` 不存在，则生成证书请求，其中包含与证书一致的 `subjectAltName`；已存在的证书请求与当前主体或 `subjectAltName` 不一致时会重新生成。
- 使用 CA 证书与私钥签发 `<CN>.cer`。
- 用于签发的 CA 证书必须为 CA 证书且允许证书签名，否则报错。
- 生成 `<CN>` 的完整证书链 `fullchain.cer`，内容为 `<CN>.cer` 与 `--chain` 指定文件内容的拼接。
- 将域名证书记录写入数据库，类型为 `cert`，名称为 `CN`。
- 证书 `NotAfter` 取请求天数与签发 CA 的 `NotAfter` 中的较小值，保证不超过签发者有效期。
- 若签发 CA 不带 SKI，则使用其公钥的 SHA-1 摘要作为 AKI。

密钥用法依据密钥类型自动确定：ECDSA 私钥使用 `digitalSignature`；RSA 私钥使用 `digitalSignature,keyEncipherment`。扩展密钥用法为 `serverAuth,clientAuth`，`basicConstraints` 为 `CA:FALSE`。签名摘要算法固定为 SHA-256。

### 签署外部证书请求

通过 `--csr` 可以签署由他人提供的证书请求，流程如下：

- 解析请求文件并校验其签名，签名无效或格式错误时报错。
- 使用请求中的公钥与主体信息，不再生成本地私钥；`--cipher`、`--rsa-bits`、`--subject` 在该模式下不生效。
- `subjectAltName` 默认取请求中的域名；若另外通过 `-d` 指定域名，则以 `-d` 为准。
- 通用名称取首个域名；若请求主体自带 `CN`，会保留并确保其出现在 `subjectAltName` 中。
- 输出目录与本地生成时一致，为 `<dir>/certs/<CN>_<密钥类型>`，其中密钥类型根据请求的公钥自动判断（`ecc`、`rsa`、`ed25519`）。
- 该模式下只写入 `<CN>.cer`、外部请求副本 `<CN>.csr` 与 `fullchain.cer`，不写入 `<CN>.key`；数据库记录中的 `key_path` 为空。

### 输出文件

在 `<dir>/certs/<CN>_<cipher>/` 下：

| 文件 | 说明 |
| --- | --- |
| `<CN>.key` | 私钥，权限 0600；使用 `--csr` 时不生成 |
| `<CN>.csr` | 证书请求，包含与证书一致的 `subjectAltName`；使用 `--csr` 时为外部请求的副本 |
| `<CN>.cer` | 域名证书 |
| `fullchain.cer` | 域名证书与证书链拼接的完整链 |

## db：管理证书数据库

数据库文件固定为 CA 目录下的 `xcert.db`，通过持久参数 `-D` / `--dir` 指定 CA 目录，默认 `.`。该参数可放在子命令之前或之后。

### 子命令

| 子命令 | 说明 |
| --- | --- |
| `db list` | 列出数据库中的全部记录 |
| `db show <serial\|name>` | 按序列号或名称显示一条记录 |
| `db delete <serial\|name>` | 按序列号或名称删除一条记录 |
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

### revoke / unrevoke 参数

在 `-D` / `--dir` 之外，还支持以下参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--ca-cert` | `<dir>/InteCA.cer` | 用于签发 CRL 的 CA 证书 |
| `--ca-key` | `<dir>/InteCA.key` | 用于签发 CRL 的 CA 私钥 |
| `--crl` | `<dir>/crl/<CA 文件名>.crl` | CRL 输出路径 |
| `--crl-days` | `30` | CRL 的 `nextUpdate` 相对于当前时间的天数 |

`revoke` 会先将匹配记录的状态更新为 `R` 并记录吊销时间，然后重新生成 CRL；`unrevoke` 会先将状态恢复为 `V` 并清除吊销时间，然后重新生成 CRL。若 CRL 生成失败，命令会报错并回滚状态修改，保持数据库与 CRL 一致。

CRL 使用 `X509 CRL` PEM 格式，CRL 编号来自数据库 `meta` 表中的独立递增计数器。CRL 内容包含数据库中所有状态为 `R` 的域名证书记录。

### delete 行为

`db delete` 仅删除数据库记录，不会删除对应的证书、私钥等文件。

## 证书能力参数详解

`--key-usage`、`--ext-key-usage`、`--path-length`、`--digest`、`--subject-key-id`、`--authority-key-id` 仅 `root` 与 `inte` 支持。

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

### --path-length

CA 路径长度限制。取值 `-1` 表示不写入路径长度限制；`0` 表示只允许签发终端证书，不允许再签发下级 CA；大于 `0` 表示允许的下级 CA 层级数。

### --digest

签名摘要算法，可选 `sha256`、`sha384`、`sha512`。会根据密钥类型自动选择对应算法（RSA 使用 RSASSA-PKCS1-v1_5，ECC 使用 ECDSA）。

### --subject-key-id 与 --authority-key-id

用于控制是否包含 SKI 与 AKI 扩展。

标准库在生成 CA 证书时会强制加入 SKI，并在由上级 CA 签发时根据父证书的 SKI 自动派生 AKI。为支持关闭这两个扩展：

- 当 `--subject-key-id=false` 时，工具改为手动编码 `basicConstraints` 扩展，并让标准库不将证书视为 CA 以跳过自动生成 SKI。生成的证书仍带有正确的 `CA:TRUE` 扩展，证书链可正常验证。
- 当 `--authority-key-id=false` 时，工具在签发前清空父证书对象中的 SKI，使标准库无法派生出 AKI。

## 密钥与文件格式

- ECC 私钥：secp256r1（prime256v1 / P-256），PEM 类型 `EC PRIVATE KEY`
- RSA 私钥：PEM 类型 `RSA PRIVATE KEY`（PKCS#1）
- 证书：PEM 类型 `CERTIFICATE`
- 证书请求：PEM 类型 `CERTIFICATE REQUEST`
- CRL：PEM 类型 `X509 CRL`
- 私钥文件权限为 `0600`，其余文件权限为 `0644`

## 目录结构示例

执行 `xcert root -D ./ca`、`xcert inte -D ./ca -c ./ca/RootCA.cer -k ./ca/RootCA.key`、`xcert cert -D ./ca -d example.com -d www.example.com` 后，目录结构如下：

```
ca
├── RootCA.key
├── RootCA.cer
├── InteCA.key
├── InteCA.csr
├── InteCA.cer
├── chain.cer
├── xcert.db
├── certs
│   └── example.com_ecc
│       ├── example.com.key
│       ├── example.com.csr
│       ├── example.com.cer
│       └── fullchain.cer
├── newcerts
└── crl
    └── InteCA.crl
```

## 数据库结构

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

序列号默认使用 128 位随机数，不占用数据库计数器；使用 `--sequential-serial` 时读取 `serial` 计数器（初始为 `01`）并递增。`root` 始终使用随机序列号。CRL 编号使用独立的 `crl` 计数器。

## 协议符合性

证书生成逻辑依据以下规范设计：

- RFC 5280：证书有效期不超出签发者；`keyUsage` 与 `basicConstraints` 扩展；签发者密钥标识符（AKI）计算。
- RFC 6125：主机名始终通过 `subjectAltName` 表达，`CN` 与 `subjectAltName` 保持一致。
- RFC 5480：ECDSA 证书的 `keyUsage` 不含 `keyEncipherment`。
- CA/Browser Forum Baseline Requirements：服务器证书签名摘要使用 SHA-256；CA 证书包含 `keyCertSign`；RSA 密钥长度不小于 2048；序列号包含至少 64 位密码学安全随机数。
- 生成的证书 `NotBefore` 相对当前时间回拨 1 分钟，避免客户端时钟偏差导致证书被视为尚未生效。

## 项目结构

```
.
├── cmd/xcert/        命令行入口，每个子命令一个 cmd_*.go 文件
├── log/              日志等级与输出
├── option/           命令行参数结构体
├── pki/              密钥与证书操作
├── store/            SQLite 证书数据库
├── Makefile
├── go.mod
├── LICENSE
└── README.md
```

## 许可证

本项目采用 MIT 许可证，详见 `LICENSE` 文件。
