# 项目约定

## 提交

- 每次提交前必须同步更新 `README.md`，确保其中记录的子命令、参数、默认值、文件布局与行为与代码一致。
- 仅在用户明确要求提交时才执行提交，且提交前先运行 `go vet ./...` 与 `go test ./...`。

## 构建与测试

- 构建：`make build` 或 `go build -o xcert ./cmd/xcert`
- 测试：`make test` 或 `go test ./...`

## 目录结构

- `cmd/xcert/`：命令行入口，每个子命令一个 `cmd_*.go` 文件
- `pki/`：密钥与证书操作
- `store/`：SQLite 证书数据库
- `option/`：命令行参数结构体
- `log/`：日志等级与输出
- 命令帮助由 cobra 依据 `Short` 与参数说明自动生成，不在代码中硬编码帮助文本

## 参数风格

统一采用 GNU kebab-case 长选项风格：

- CA 目录统一为 `-D` / `--dir`
- 长选项使用连字符，例如 `--rsa-bits`、`--path-length`、`--digest`、`--sequential-serial`、`--crl-days`
- 高频操作保留短选项，其余仅提供长选项
