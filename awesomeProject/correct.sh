# 1) 清理掉之前失败/冲突的构建产物（可选）
rm -f ./main

# 2) 把 gnark-crypto 固定到 kryptology 兼容的版本
go get github.com/consensys/gnark-crypto@v0.5.3

# 如遇其他依赖把它又升上去，可强制替换（任选其一用就行）
# go mod edit -replace=github.com/consensys/gnark-crypto=github.com/consensys/gnark-crypto@v0.5.3

# 3) 整理依赖
go mod tidy

# 4) 重新编译（自动识别架构）
arch=$(uname -m); case "$arch" in x86_64) GOARCH=amd64;; aarch64|arm64) GOARCH=arm64;; *) echo "unsupported arch: $arch"; exit 1;; esac
GOOS=linux GOARCH=$GOARCH go build -trimpath -ldflags "-s -w" -o main main.go

# 5) 验证二进制
ls -l ./main
file ./main   # 应该是 ELF 64-bit 可执行文件（非空且带 x 权限）
