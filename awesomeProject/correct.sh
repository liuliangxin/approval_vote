
rm -f ./main


go get github.com/consensys/gnark-crypto@v0.5.3





go mod tidy


arch=$(uname -m); case "$arch" in x86_64) GOARCH=amd64;; aarch64|arm64) GOARCH=arm64;; *) echo "unsupported arch: $arch"; exit 1;; esac
GOOS=linux GOARCH=$GOARCH go build -trimpath -ldflags "-s -w" -o main main.go


ls -l ./main
file ./main   
