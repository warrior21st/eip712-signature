package main

import (
	"fmt"
	"strings"
	"time"

	//"crypto/sha256"

	"github.com/gin-gonic/gin"
)

type EIP712BaseParams struct {
	typeStr        string
	name           string
	chainId        string
	version        string
	verifyContract string
}

func main() {

	r := gin.Default()

	r.POST("/sign", sign)
	r.POST("/verify", verifyEIP712Signature)

	r.Run(":6000") // listen and serve on 0.0.0.0:8080
}

func LogToConsole(msg string) {
	fmt.Println(strings.Join([]string{time.Now().UTC().Add(8 * time.Hour).Format("2006-01-02 15:04:05"), "  ", msg}, ""))
}
