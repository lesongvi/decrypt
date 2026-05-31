# decrypt

A Go port of an SCS SII decryptor/decoder for ETS2/ATS save files.

This project supports:

- Encrypted SII files (`SrcC`)
- Plain text SII files (`SiiS`)
- Binary SII files (`BSII` / `SIIB`) with text serialization output

## Idiomatic Library Layout

The codebase is split into small, focused packages:

```text
decryptor.go                            # public facade package (sii)
decryptor_test.go                       # end-to-end library test
internal/
    app/
        decrypt/
            service.go                  # orchestrates decrypt/decode workflow
            crypto.go                   # AES-256-CBC + PKCS#7 decrypt helpers
            bsii.go                     # safe BSII decode adapter
  bsii/
        decode.go                       # BSII structure/data block parser
        decoder/decoder_utils.go        # low-level type decoders
        serializer/bsii_serializer.go   # BSII -> SiiNunit text serializer
    model/types.go                      # shared models, signatures, enums
  stream/stream_utils.go                # safe stream read helpers
tests/
    testdata/
        game.sii
        game_unencrypted.sii
```

## Install

This repository is currently used as a module source. In your own project:

```bash
go get lsv.vn/go/sii_decrypt
```

## Basic Usage

```go
package main

import (
    "fmt"
    "os"

    sii "lsv.vn/go/sii_decrypt"
)

func main() {
    filePath := "./save_game.sii"

    if _, err := os.Stat(filePath); err != nil {
        fmt.Println("file not found:", filePath)
        return
    }

    result, err := sii.Decrypt(filePath, true)
    if err != nil {
        fmt.Println("decrypt error:", err)
        return
    }

    if !result.Success {
        fmt.Println("decrypt failed")
        return
    }

    if err := os.WriteFile("./decoded_save_game.sii", result.Data, 0o644); err != nil {
        fmt.Println("write error:", err)
        return
    }

    fmt.Println("type:", result.Type)
    fmt.Println("encrypted:", result.Encrypted)
    fmt.Println("decoded bytes:", len(result.Data))
}
```

## Advanced Usage

```go
package main

import (
    "encoding/binary"
    "fmt"
    "os"

    sii "lsv.vn/go/sii_decrypt"
)

func main() {
    filePath := "./save_game.sii"
    raw, err := os.ReadFile(filePath)
    if err != nil {
        fmt.Println("read error:", err)
        return
    }

    if len(raw) < 4 {
        fmt.Println("invalid file")
        return
    }

    sig := binary.LittleEndian.Uint32(raw[:4])
    switch sig {
    case sii.SignatureType["Encrypted"]:
        fmt.Println("file type: encrypted")
    case sii.SignatureType["PlainText"]:
        fmt.Println("file type: plain")
    case sii.SignatureType["Binary"]:
        fmt.Println("file type: binary")
    default:
        fmt.Println("file type: unknown")
    }

    result, err := sii.Decrypt(filePath, true)
    if err != nil {
        fmt.Println("decrypt error:", err)
        return
    }

    text := string(result.Data)
    previewLimit := 500
    if len(text) < previewLimit {
        previewLimit = len(text)
    }

    fmt.Println("preview:")
    fmt.Println(text[:previewLimit])
}
```

## Public API

- `Decrypt(filePath string, decode bool) (DecryptResult, error)`
- `DecryptBytes(data []byte, decode bool) (DecryptResult, error)`
- `DecodeBinaryData(data []byte) (*DecodeResult, error)`
- `NewDecryptor() Decryptor`
- `Decryptor{}.Decrypt(filePath string, decode bool) (DecryptResult, error)`
- `Decryptor{}.DecryptBytes(data []byte, decode bool) (DecryptResult, error)`
- `Decryptor{}.DecodeBinaryData(data []byte) (*DecodeResult, error)`

Useful exported maps/constants:

- `SignatureType`
- `DataTypeIdFormat`

## Notes

- `_3nK` decoding is not implemented yet.
- This is an unofficial implementation based on reverse-engineered format behavior.
- For malformed encrypted input, decryption now returns errors instead of panicking.
