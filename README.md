# go-authcode
 discuz authcode  for golang to achieve

# example
```javascript
package main

import (
	"fmt"
	"authcode"
)

func main() {
	
	str 	:= "hello authcode"
	encode 	:= authcode.AuthCode(str, "ENCODE", "", 0)
	fmt.Println(encode)
	
	decode 	:= authcode.AuthCode(encode, "DECODE", "", 0)
	fmt.Println(decode)
	
	/**
	output
	
	2e38p2jIvSP*Owanmp3x0fNFEsLFzcE5ZLPsAUgWhIvQqgRcf7lqpvgIRA==
	hello authcode

	**/
}
```
