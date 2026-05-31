package sii_test

import (
	"os"
	"path/filepath"
	"testing"

	sii "lsv.vn/go/sii_decrypt"
)

func BenchmarkDecryptFile_GameSII(b *testing.B) {
	inputPath := filepath.Join("tests", "testdata", "game.sii")

	if _, err := os.Stat(inputPath); err != nil {
		b.Fatalf("missing input fixture: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := sii.Decrypt(inputPath, true)
		if err != nil {
			b.Fatalf("decrypt failed: %v", err)
		}
		if !result.Success {
			b.Fatalf("decrypt returned success=false")
		}
	}
}

func BenchmarkDecryptBytes_GameSII(b *testing.B) {
	inputPath := filepath.Join("tests", "testdata", "game.sii")
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		b.Fatalf("failed reading fixture: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := sii.DecryptBytes(raw, true)
		if err != nil {
			b.Fatalf("decrypt failed: %v", err)
		}
		if !result.Success {
			b.Fatalf("decrypt returned success=false")
		}
	}
}
