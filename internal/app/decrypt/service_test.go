package decrypt

import (
	"encoding/binary"
	"strings"
	"testing"

	"lsv.vn/go/sii_decrypt/internal/model"
)

func TestProcessPlainText_NoDecode(t *testing.T) {
	payload := []byte("SiiNunit\n{\n}\n")
	buf := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(buf[:4], model.SignaturePlainText)
	copy(buf[4:], payload)

	svc := NewService()
	result, err := svc.Process(buf, false)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success=true")
	}
	if result.Type != "plain" {
		t.Fatalf("expected type plain, got %s", result.Type)
	}
	if len(result.Data) != len(buf) {
		t.Fatalf("expected data length %d, got %d", len(buf), len(result.Data))
	}
}

func TestProcessUnsupportedSignature(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[:4], model.SignatureType["Unknown"])

	svc := NewService()
	_, err := svc.Process(buf, true)
	if err == nil {
		t.Fatalf("expected unsupported signature error")
	}
	if !strings.Contains(err.Error(), "unsupported decoded signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptFileNotFound(t *testing.T) {
	svc := NewService()
	_, err := svc.DecryptFile("./not-exists.sii", true)
	if err == nil {
		t.Fatalf("expected file not found error")
	}
	if !strings.Contains(err.Error(), "file does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptPayloadValidation(t *testing.T) {
	_, err := decryptPayload([]byte{0x01, 0x02}, DefaultKey)
	if err == nil {
		t.Fatalf("expected short payload error")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("unexpected error: %v", err)
	}

	bad := make([]byte, 56+15)
	_, err = decryptPayload(bad, DefaultKey)
	if err == nil {
		t.Fatalf("expected block-size error")
	}
	if !strings.Contains(err.Error(), "multiple of AES block size") {
		t.Fatalf("unexpected error: %v", err)
	}
}
