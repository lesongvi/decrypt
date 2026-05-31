package sii_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sii "lsv.vn/go/sii_decrypt"
)

func TestDecryptGameSII_MatchesGoldenOutput(t *testing.T) {
	inputPath := filepath.Join("tests", "testdata", "game.sii")
	goldenPath := filepath.Join("tests", "testdata", "game_unencrypted.sii")

	if _, err := os.Stat(inputPath); err != nil {
		t.Fatalf("missing input file %s: %v", inputPath, err)
	}
	if _, err := os.Stat(goldenPath); err != nil {
		t.Fatalf("missing golden file %s: %v", goldenPath, err)
	}

	result, err := sii.Decrypt(inputPath, true)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("decrypt returned success=false")
	}

	goldenData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed reading golden output: %v", err)
	}

	if !bytes.Equal(result.Data, goldenData) {
		t.Fatalf("decrypted output mismatch: got %d bytes, want %d bytes", len(result.Data), len(goldenData))
	}
}

func TestDecryptBytes_PlainText(t *testing.T) {
	payload := []byte("SiiNunit\n{\n}\n")
	buf := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(buf[:4], sii.SignatureType["PlainText"])
	copy(buf[4:], payload)

	result, err := sii.DecryptBytes(buf, true)
	if err != nil {
		t.Fatalf("DecryptBytes failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("DecryptBytes returned success=false")
	}
	if result.Type != "plain" {
		t.Fatalf("expected type plain, got %s", result.Type)
	}
	if !bytes.Equal(result.Data, buf) {
		t.Fatalf("plaintext payload changed unexpectedly")
	}
}

func TestDecryptorFacade_MissingFile(t *testing.T) {
	d := sii.NewDecryptor()
	_, err := d.Decrypt("./tests/testdata/not_found.sii", true)
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "file does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
}
