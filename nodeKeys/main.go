package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {

	basePath := `/root/approve_vote/awesomeProject`
	nodetablePath := filepath.Join(basePath, "nodetable1.csv")
	filesksPath := filepath.Join(basePath, "filesks1.txt")

	nodeTable := make(map[string]string)
	for i := 1; i <= 500; i++ {
		// ：1111 + (i-1)
		addr := fmt.Sprintf("172.24.114.144:%d", 1110+i)
		nodeTable[fmt.Sprintf("%d", i)] = addr
	}

	//
	data, err := json.MarshalIndent(nodeTable, "", "  ")
	if err != nil {
		panic(err)
	}

	//
	if err := os.WriteFile(nodetablePath, data, 0644); err != nil {
		panic(err)
	}
	fmt.Println(" nodetable1.csv :", nodetablePath)

	// 2.
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
	fmt.Println(" filesks1.txt :", filesksPath)
}
