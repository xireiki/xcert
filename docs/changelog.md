# 更新日志

本文件记录 xcert 的显著变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增

- `root`、`inte`、`cert` 子命令，用于生成根 CA、中间 CA 与域名证书。
- 支持 ECC（prime256v1 / P-256）、RSA（不小于 2048 位）与 ed25519 私钥。
- `info` 子命令，查看任意证书文件的详细信息。
- `db` 子命令，提供查询、导入、删除、吊销、解除吊销与 CRL 生成。
- `cert --code-signing`，生成 Windows 代码签名证书（PKCS#12 / PFX）。
- `cert --csr`，签署由外部提供的证书请求。
- 可自定义密钥用法、扩展密钥用法、CA 路径长度、签名摘要算法与 SKI/AKI 开关。
- 全局 `--legacy` 选项，读取旧 `xcert.sh` 目录的序列号与记录。

### 变更

- 分级日志与彩色输出，数据输出与日志分离。
- 证书有效期自动收敛到签发者有效期内。
- 默认使用随机序列号，可通过 `--sequential-serial` 切换为数据库递增序列号。

### 修复

- 证书通用名称的路径安全校验，避免输出路径逃逸 CA 目录。
- 删除证书时同步清理相关文件并刷新 CRL。
- CRL 生成失败时回滚吊销状态，保持数据库与 CRL 一致。
