# README

## 1. 环境准备

* **Go 1.24.1**（必须）



## 2. 获取代码


> 若在国内网络，建议设置 Go 代理（可选）：

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

## 3. 拉取依赖

在项目根目录（含 `go.mod` 的目录）执行：

cd awesomeProject            # 进入含有 go.mod 的根目录
go mod tidy   

```bash
go mod tidy
```

如果需要同时构建/运行 `DKG/` 子模块（其下也有独立 `go.mod`）：

```bash
cd DKG
go mod tidy
cd ..
```

## 4. 启动节点（Windows）

在项目根目录（含有 `a.bat` 的目录）执行：

```bat
a.bat
```

或在文件管理器中**双击** `a.bat`。

> `a.bat` 会按脚本逻辑启动节点；日志通常在 `logs/` 目录下

`DKG/` 子模块（如需）：

```bash
cd DKG
go run .
# 或
go build -o ../bin/dkg .
../bin/dkg   # Windows: ..\bin\dkg.exe
```

