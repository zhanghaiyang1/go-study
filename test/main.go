package main

import (

	"fmt"
	"strings"
)


func main (){
	url := "https://www.qbao100.com/some/path"

    if strings.HasPrefix(url, "https://www.qbao100.com") {
        fmt.Println("The URL starts with https://www.qbao100.com")
    } else {
        fmt.Println("The URL does not start with https://www.qbao100.com")
    }
}
