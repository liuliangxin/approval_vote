package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// 路径
	basePath := `/root/approve_vote/awesomeProject`
	nodetablePath := filepath.Join(basePath, "nodetable1.csv")
	filesksPath := filepath.Join(basePath, "filesks1.txt")

	// 1. 生成节点地址表
	nodeTable := make(map[string]string)
	for i := 1; i <= 500; i++ {
		// 端口号递增：1111 + (i-1)
		addr := fmt.Sprintf("172.24.114.144:%d", 1110+i)
		nodeTable[fmt.Sprintf("%d", i)] = addr
	}

	// 转换为 JSON 格式
	data, err := json.MarshalIndent(nodeTable, "", "  ")
	if err != nil {
		panic(err)
	}

	// 写入 nodetable1.csv
	if err := os.WriteFile(nodetablePath, data, 0644); err != nil {
		panic(err)
	}
	fmt.Println("生成 nodetable1.csv 成功:", nodetablePath)

	// 2. 生成 filesks1.txt
	f, err := os.Create(filesksPath)
	if err != nil {
		panic(err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	for i := 1; i <= 500; i++ {
		_, err := f.WriteString(fmt.Sprintf("%d\n", i))
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("生成 filesks1.txt 成功:", filesksPath)
}
