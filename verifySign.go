package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/warrior21st/blockchain-utils/ethutil"
)

func verifyEIP712Signature(c *gin.Context) {
	statusCode := 200
	message := ""
	result := "false"

	var f interface{}
	err := c.ShouldBindJSON(&f)
	if err != nil {
		statusCode = 400
		message = err.Error()
	} else {
		m := f.(map[string]interface{})

		typeStr := "typeStr(string account,address userAddress,uint256 deadline)"
		nameStr := "nameStr"
		chainIdStr := m["chainId"].(string)
		accountStr := m["account"].(string)
		addressHex := m["address"].(string)
		deadlineStr := m["deadline"].(string)
		v := m["v"].(string)
		r := m["r"].(string)
		s := m["s"].(string)
		rsv := append(common.FromHex(r), common.FromHex(s)...)
		rsv = append(rsv, common.FromHex(v)...)

		typeHash := crypto.Keccak256([]byte(typeStr))
		nameHash := crypto.Keccak256([]byte(nameStr))
		chainId, _ := big.NewInt(0).SetString(chainIdStr, 10)

		account := crypto.Keccak256([]byte(accountStr))
		address := common.HexToAddress(addressHex)
		deadline, _ := big.NewInt(0).SetString(deadlineStr, 10)

		domainSeparatorPacked := crypto.Keccak256([]byte("EIP712Domain(string name,uint256 chainId)"))
		domainSeparatorPacked = append(domainSeparatorPacked, nameHash...)
		domainSeparatorPacked = append(domainSeparatorPacked, ethutil.FillTo32Bytes(chainId.Bytes())...)
		domainSeparatorHash := crypto.Keccak256(domainSeparatorPacked)

		dataPacked := typeHash
		dataPacked = append(dataPacked, ethutil.FillTo32Bytes(account)...)
		dataPacked = append(dataPacked, ethutil.FillTo32Bytes(address.Bytes())...)
		dataPacked = append(dataPacked, ethutil.FillTo32Bytes(deadline.Bytes())...)
		dataHash := crypto.Keccak256(dataPacked)

		packedParams := []byte{0x19, 0x01}
		packedParams = append(packedParams, domainSeparatorHash...)
		packedParams = append(packedParams, dataHash...)
		digest := crypto.Keccak256(packedParams)

		signAddr, err := ethutil.EcRecover(digest, rsv)
		signAddrHex := signAddr.Hex()
		if err != nil {
			statusCode = 400
			message = err.Error()
		} else {
			if big.NewInt(0).SetBytes(signAddr.Bytes()).Cmp(big.NewInt(0)) == 1 && signAddrHex == address.Hex() {
				result = "true"
			} else {
				message = "unauthorized"
			}
		}

		LogToConsole(fmt.Sprintf("EcRecover r : %s,s: %s, v: %s, expect addr: %s,recover addr: %s, ", r, s, v, addressHex, signAddr.Hex()))
	}

	c.JSON(statusCode, gin.H{
		"result": result,
		"msg":    message,
	})
}
