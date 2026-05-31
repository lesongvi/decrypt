package decrypt

import (
	"fmt"
	"runtime/debug"

	"lsv.vn/go/sii_decrypt/internal/bsii"
	"lsv.vn/go/sii_decrypt/internal/model"
)

func safeBSIIDecode(data []byte) (result *model.SIIDecodeResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("bsii decode panic: %v\n%s", r, debug.Stack())
		}
	}()

	return bsii.Decode(data)
}
