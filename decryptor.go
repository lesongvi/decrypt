// Copyright 2026 lesongvi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sii

import (
	"lsv.vn/go/sii_decrypt/internal/app/decrypt"
	"lsv.vn/go/sii_decrypt/internal/model"
)

var SiiKey = append([]byte(nil), decrypt.DefaultKey...)

// Re-export core enums/types so callers don't need internal package imports.
var SignatureType = model.SignatureType
var DataTypeIdFormat = model.DataTypeIdFormat

type DecryptResult = model.SIIDecryptResult
type BinaryFormatInfo = model.BinaryFormatInfo
type DecodeResult = model.SIIDecodeResult

type Decryptor struct{}

func NewDecryptor() Decryptor {
	return Decryptor{}
}

func (Decryptor) Decrypt(filePath string, decode bool) (DecryptResult, error) {
	return Decrypt(filePath, decode)
}

func (Decryptor) DecodeBinaryData(data []byte) (*DecodeResult, error) {
	return DecodeBinaryData(data)
}

func (Decryptor) DecryptBytes(data []byte, decode bool) (DecryptResult, error) {
	return DecryptBytes(data, decode)
}

func Decrypt(filePath string, decode bool) (DecryptResult, error) {
	return decrypt.NewServiceWithKey(SiiKey).DecryptFile(filePath, decode)
}

func DecodeBinaryData(data []byte) (*DecodeResult, error) {
	return decrypt.NewServiceWithKey(SiiKey).DecodeBinaryData(data)
}

func DecryptBytes(data []byte, decode bool) (DecryptResult, error) {
	return decrypt.NewServiceWithKey(SiiKey).Process(data, decode)
}
