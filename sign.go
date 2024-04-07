package main

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/warrior21st/blockchain-utils/ethutil"
)

func sign(c *gin.Context) {

	var f interface{}
	err := c.ShouldBindJSON(&f)
	if err != nil {
		c.JSON(400, gin.H{
			"message": err.Error(),
			"data":    nil,
		})
		return
	}

	m := f.(map[string]interface{})
	prvHex := m["signerPrv"].(string)

	eip712Paras := EIP712BaseParams{
		typeStr:        m["type"].(string),
		name:           m["name"].(string),
		chainId:        m["chainId"].(string),
		verifyContract: m["verifyContract"].(string),
	}

	signParams := m["signParams"].(map[string]interface{})
	signR, signS, signV, err := genEIP712Signature(eip712Paras, prvHex, signParams)
	if err != nil {
		c.JSON(400, gin.H{
			"message": err.Error(),
			"data":    nil,
		})
		return
	}
	rsvJson := fmt.Sprintf("{\"r\":\"%s\",\"s\":\"%s\",\"v\":\"%s\"}", signR, signS, signV)

	LogToConsole(rsvJson)

	c.JSON(200, gin.H{
		"message": "",
		"data":    rsvJson,
	})
}

func genEIP712Signature(baseParas EIP712BaseParams, prvHex string, signParams map[string]interface{}) (r string, s string, v string, err error) {
	tokenHex := signParams["token"].(string)
	accountHex := signParams["account"].(string)
	amountStr := signParams["amount"].(string)
	randHex := signParams["rand"].(string)

	LogToConsole(fmt.Sprintf("signing chainId: %s,type: %s, token: %s, account: %s, amount: %s, rand: %s...", baseParas.chainId, baseParas.typeStr, tokenHex, accountHex, amountStr, randHex))

	typeHash := crypto.Keccak256([]byte(baseParas.typeStr))
	name := crypto.Keccak256([]byte(baseParas.name))
	// version := crypto.Keccak256([]byte(versionStr))
	chainId, b := big.NewInt(0).SetString(baseParas.chainId, 10)
	if !b {
		return "", "", "", errors.New("chain id can not parse to big int")
	}
	verifyContract := common.HexToAddress(baseParas.verifyContract)

	token := common.HexToAddress(tokenHex)
	account := common.HexToAddress(accountHex)
	amount, b := big.NewInt(0).SetString(amountStr, 10)
	if !b {
		return "", "", "", errors.New("amount can not parse to big int")
	}
	rand := common.FromHex(randHex)

	domainSeparatorPacked := crypto.Keccak256([]byte("EIP712Domain(string name,uint256 chainId,address verifyingContract)"))
	domainSeparatorPacked = append(domainSeparatorPacked, name...)
	domainSeparatorPacked = append(domainSeparatorPacked, ethutil.FillTo32Bytes(chainId.Bytes())...)
	domainSeparatorPacked = append(domainSeparatorPacked, ethutil.FillTo32Bytes(verifyContract.Bytes())...)
	domainSeparatorHash := crypto.Keccak256(domainSeparatorPacked)

	dataPacked := typeHash
	dataPacked = append(dataPacked, ethutil.FillTo32Bytes(account.Bytes())...)
	dataPacked = append(dataPacked, ethutil.FillTo32Bytes(token.Bytes())...)
	dataPacked = append(dataPacked, ethutil.FillTo32Bytes(amount.Bytes())...)
	dataPacked = append(dataPacked, ethutil.FillTo32Bytes(rand)...)
	dataHash := crypto.Keccak256(dataPacked)

	packedParams := []byte{0x19, 0x01}
	packedParams = append(packedParams, domainSeparatorHash...)
	packedParams = append(packedParams, dataHash...)
	digest := crypto.Keccak256(packedParams)

	signature := ethutil.SignMessage(digest, ethutil.HexToECDSAPrivateKey(prvHex))

	r = ethutil.Bytes2HexWith0x(signature.R)
	s = ethutil.Bytes2HexWith0x(signature.S)
	v = ethutil.Bytes2HexWith0x(big.NewInt(int64(signature.V)).Bytes())

	return
}
