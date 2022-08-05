package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)



func main(){
	fmt.Println("md5---")
	h := md5.New()
	h.Write([]byte("0468a8ae77314b99b3e737cd0c84da50"))
	sign := hex.EncodeToString(h.Sum(nil))
	fmt.Println("sign:", sign)
}