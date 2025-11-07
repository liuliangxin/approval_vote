package priacy_compute

import (
	"crypto/sha256"
	"encoding/hex"
)

// Merkle 树节点
type MerkleNode struct {
	Hash  []byte
	Left  *MerkleNode
	Right *MerkleNode
}

// 构建 Merkle 树
func BuildMerkleTree(leaves [][]byte) *MerkleNode {
	var nodes []*MerkleNode
	for _, leaf := range leaves {
		nodes = append(nodes, &MerkleNode{Hash: leaf})
	}

	// 构建树，直到只有一个节点
	for len(nodes) > 1 {
		var newLevel []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			// 合并两个节点
			left := nodes[i]
			var right *MerkleNode
			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				// 如果是奇数，复制一个节点
				right = left
			}

			// 合并哈希值
			combinedHash := append(left.Hash, right.Hash...)
			hash := sha256.Sum256(combinedHash)
			newLevel = append(newLevel, &MerkleNode{Hash: hash[:], Left: left, Right: right})
		}
		nodes = newLevel
	}

	// 返回 Merkle 树根
	return nodes[0]
}

// 获取 Merkle 路径
func GetMerklePath(leaf []byte, tree *MerkleNode) [][]byte {
	var path [][]byte
	var currentNode = tree

	// 在树中查找叶子节点
	for currentNode != nil {
		if currentNode.Left != nil && isLeaf(currentNode.Left, leaf) {
			// 如果是左子节点，记录右子节点
			if currentNode.Right != nil {
				path = append(path, currentNode.Right.Hash)
			}
			currentNode = currentNode.Left
		} else if currentNode.Right != nil && isLeaf(currentNode.Right, leaf) {
			// 如果是右子节点，记录左子节点
			if currentNode.Left != nil {
				path = append(path, currentNode.Left.Hash)
			}
			currentNode = currentNode.Right
		} else {
			break
		}
	}

	return path
}

// 判断节点是否为叶子节点
func isLeaf(node *MerkleNode, leaf []byte) bool {
	return hex.EncodeToString(node.Hash) == hex.EncodeToString(leaf)
}
