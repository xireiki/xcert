# 项目约定

## 提交

- 每次提交前必须同步更新 `README.md`，确保其中记录的子命令、参数、默认值、文件布局与行为与代码一致。
- 仅在用户明确要求提交时才执行提交，且提交前先运行 `go vet ./...` 与 `go test ./...`。

## 构建与测试

- 构建：`go build -o xcert .`
- 测试：`go test ./...`

## 参数风格

统一采用 GNU kebab-case 长选项风格：

- CA 目录统一为 `-D` / `--dir`
- 长选项使用连字符，例如 `--rsa-bits`、`--path-length`、`--digest`、`--random-serial`、`--crl-days`
- 高频操作保留短选项，其余仅提供长选项
