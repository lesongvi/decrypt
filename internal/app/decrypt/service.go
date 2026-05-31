package decrypt

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"os"

	"lsv.vn/go/sii_decrypt/internal/model"
	"lsv.vn/go/sii_decrypt/internal/stream"
)

var DefaultKey = []byte{
	0x2a, 0x5f, 0xcb, 0x17, 0x91, 0xd2, 0x2f, 0xb6, 0x02, 0x45, 0xb3, 0xd8,
	0x36, 0x9e, 0xd0, 0xb2, 0xc2, 0x73, 0x71, 0x56, 0x3f, 0xbf, 0x1f, 0x3c,
	0x9e, 0xdf, 0x6b, 0x11, 0x82, 0x5a, 0x5d, 0x0a,
}

type Service struct {
	key []byte
}

func NewService() Service {
	return NewServiceWithKey(DefaultKey)
}

func NewServiceWithKey(key []byte) Service {
	copiedKey := append([]byte(nil), key...)
	return Service{key: copiedKey}
}

func (s Service) DecryptFile(filePath string, decode bool) (model.SIIDecryptResult, error) {
	result := model.SIIDecryptResult{
		Data:    []byte{},
		Success: false,
		Type:    "plain",
	}

	bytesData, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return result, fmt.Errorf("file does not exist: %s", filePath)
		}
		return result, err
	}

	return s.Process(bytesData, decode)
}

func (s Service) Process(bytesData []byte, decode bool) (model.SIIDecryptResult, error) {
	result := model.SIIDecryptResult{
		Data:    []byte{},
		Success: false,
		Type:    "plain",
	}

	streamPos := 0
	fileType, success := stream.TryReadUInt32(bytesData, &streamPos)
	if !success {
		return result, errors.New("invalid file")
	}

	result.Type = fileTypeToName(fileType)
	processedBytes := bytesData

	if fileType == model.SignatureEncrypted {
		decryptedData, err := decryptPayload(bytesData, s.key)
		if err != nil {
			return result, err
		}

		zReader, err := zlib.NewReader(bytes.NewReader(decryptedData))
		if err != nil {
			return result, fmt.Errorf("failed to initialize zlib inflating: %w", err)
		}

		uncompressed, err := io.ReadAll(zReader)
		zReader.Close()
		if err != nil {
			return result, fmt.Errorf("failed inflating data: %w", err)
		}

		processedBytes = uncompressed
		result.Encrypted = true
	}

	if decode {
		streamPos = 0
		dataType, success := stream.TryReadUInt32(processedBytes, &streamPos)
		if !success {
			return result, errors.New("invalid data")
		}

		switch dataType {
		case model.SignaturePlainText:
			result.Data = processedBytes
			result.Type = "plain"
			result.Success = true
		case model.SignatureBinary:
			decodedResult, err := safeBSIIDecode(processedBytes)
			if err != nil {
				return result, err
			}
			result.Data = decodedResult.Data
			result.Type = "binary"
			result.Success = true
			result.BinaryFormatInfo = &model.BinaryFormatInfo{
				Header:  decodedResult.Header,
				Success: &decodedResult.Success,
			}
		case model.Signature3nK:
			return result, errors.New("_3nK decoding is not implemented yet")
		default:
			return result, fmt.Errorf("unsupported decoded signature: 0x%08x", dataType)
		}
	} else {
		result.Data = processedBytes
		result.Success = true
	}

	if result.Success && len(result.Data) > 0 {
		str := string(result.Data)
		result.StringContent = &str
	}

	return result, nil
}

func (s Service) DecodeBinaryData(data []byte) (*model.SIIDecodeResult, error) {
	return safeBSIIDecode(data)
}

func fileTypeToName(fileType uint32) string {
	switch fileType {
	case model.SignaturePlainText:
		return "plain"
	case model.SignatureEncrypted:
		return "encrypted"
	case model.SignatureBinary:
		return "binary"
	case model.Signature3nK:
		return "3nK"
	default:
		return "unknown"
	}
}
