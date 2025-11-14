# README

## 1. Environment Setup

* **Go 1.24.1** (required)

## 2. Get the Code

> If you are in mainland China, it’s recommended (optional) to set a Go proxy:

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

## 3. Fetch Dependencies

In the project root directory (the directory that contains `go.mod`), run:

```bash
cd awesomeProject            # enter the root directory that contains go.mod
go mod tidy
```

If you also need to build/run the `DKG/` submodule (which has its own `go.mod`):

```bash
cd DKG
go mod tidy
cd ..
```

## 4. Start the Node (Windows)

In the project root directory (the one that contains `a.bat`), run:

```bat
a.bat
```

Or **double-click** `a.bat` in File Explorer.

> `a.bat` will start the node according to the script logic; logs are usually in the `logs/` directory.

For the `DKG/` submodule (if needed):

```bash
cd DKG
go run .
# or
go build -o ../bin/dkg . 
../bin/dkg   # Windows: ..\bin\dkg.exe
```

---

## 5. Start the Node (Linux/Mac)

In the project directory `approve_vote/awesomeProject/`, run the following command to open the port and start the node:

```bash
bash a.sh
```

---

This completes the README with all necessary instructions for setting up the environment, fetching dependencies, starting the node on different systems, and troubleshooting the logs.

