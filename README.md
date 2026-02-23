# SSCE
A simple shellcode encoder, it supports custom decoder and loader templates.

## Usage
```bash
ssce -arch 64 -i shellcode.bin -o shellcode_x64.bin
```

## Development
```go
package main

import (
    "encoding/hex"
    "fmt"
    "os"

    "github.com/RTS-Framework/SSCE"
)

func main() {
    encoder := ssce.NewEncoder()

    shellcode, err := os.ReadFile("shellcode.bin")
    checkError(err)

    opts := ssce.Options{
        NumIterator: 4,
        NumTailInst: 64,
        MinifyMode:  false,
        SaveContext: false,
        EraseInst:   false,
        NoIterator:  false,
        NoGarbage:   false,
    }

    ctx, err := encoder.Encode(shellcode, 64, &opts)
    checkError(err)

    out := hex.EncodeToString(ctx.Output)
    fmt.Println(out)

    err = encoder.Close()
    checkError(err)
}

func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
```
## Disclaimer
This project is for research purposes only and is strictly prohibited from being used for illegal purposes.
