package priacy_compute

import (
	"crypto/sha256"
	"encoding/hex"
)

type MerkleNode struct {
	Hash  []byte
	Left  *MerkleNode
	Right *MerkleNode
}

func BuildMerkleTree(leaves [][]byte) *MerkleNode {
	var nodes []*MerkleNode
	for _, leaf := range leaves {
		nodes = append(nodes, &MerkleNode{Hash: leaf})
	}

	for len(nodes) > 1 {
		var newLevel []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {

			left := nodes[i]
			var right *MerkleNode
			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {

				right = left
			}

			combinedHash := append(left.Hash, right.Hash...)
			hash := sha256.Sum256(combinedHash)
			newLevel = append(newLevel, &MerkleNode{Hash: hash[:], Left: left, Right: right})
		}
		nodes = newLevel
	}

	return nodes[0]
}

func GetMerklePath(leaf []byte, tree *MerkleNode) [][]byte {
	var path [][]byte
	var currentNode = tree

	for currentNode != nil {
		if currentNode.Left != nil && isLeaf(currentNode.Left, leaf) {

			if currentNode.Right != nil {
				path = append(path, currentNode.Right.Hash)
			}
			currentNode = currentNode.Left
		} else if currentNode.Right != nil && isLeaf(currentNode.Right, leaf) {

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

func isLeaf(node *MerkleNode, leaf []byte) bool {
	return hex.EncodeToString(node.Hash) == hex.EncodeToString(leaf)
}
