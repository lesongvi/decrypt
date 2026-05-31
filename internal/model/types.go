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

package model

const (
	SignatureUnknown   uint32 = 999
	SignaturePlainText uint32 = 1315531091
	SignatureEncrypted uint32 = 1131635539
	SignatureBinary    uint32 = 1229542210
	Signature3nK       uint32 = 21720627
)

const (
	BSIIVersion1 uint32 = 1
	BSIIVersion2 uint32 = 2
	BSIIVersion3 uint32 = 3
)

const (
	DataTypeUTF8String             uint32 = 0x01
	DataTypeArrayOfUTF8String      uint32 = 0x02
	DataTypeEncodedString          uint32 = 0x03
	DataTypeArrayOfEncodedString   uint32 = 0x04
	DataTypeSingle                 uint32 = 0x05
	DataTypeArrayOfSingle          uint32 = 0x06
	DataTypeVectorOf2Single        uint32 = 0x07
	DataTypeArrayOfVectorOf2Single uint32 = 0x08
	DataTypeVectorOf3Single        uint32 = 0x09
	DataTypeArrayOfVectorOf3Single uint32 = 0x0a
	DataTypeVectorOf3Int32         uint32 = 0x11
	DataTypeArrayOfVectorOf3Int32  uint32 = 0x12
	DataTypeVectorOf4Single        uint32 = 0x17
	DataTypeArrayOfVectorOf4Single uint32 = 0x18
	DataTypeVectorOf8Single        uint32 = 0x19
	DataTypeArrayOfVectorOf8Single uint32 = 0x1a
	DataTypeInt32                  uint32 = 0x25
	DataTypeArrayOfInt32           uint32 = 0x26
	DataTypeUInt32                 uint32 = 0x27
	DataTypeArrayOfUInt32          uint32 = 0x28
	DataTypeInt16                  uint32 = 0x29
	DataTypeArrayOfInt16           uint32 = 0x2a
	DataTypeUInt16                 uint32 = 0x2b
	DataTypeArrayOfUInt16          uint32 = 0x2c
	DataTypeUInt32Type2            uint32 = 0x2f
	DataTypeInt64                  uint32 = 0x31
	DataTypeArrayOfInt64           uint32 = 0x32
	DataTypeUInt64                 uint32 = 0x33
	DataTypeArrayOfUInt64          uint32 = 0x34
	DataTypeByteBool               uint32 = 0x35
	DataTypeArrayOfByteBool        uint32 = 0x36
	DataTypeOrdinalString          uint32 = 0x37
	DataTypeId                     uint32 = 0x39
	DataTypeArrayOfIdA             uint32 = 0x3a
	DataTypeIdType2                uint32 = 0x3b
	DataTypeArrayOfIdC             uint32 = 0x3c
	DataTypeIdType3                uint32 = 0x3d
	DataTypeArrayOfIdE             uint32 = 0x3e
)

var SignatureType = map[string]uint32{
	"Unknown":   SignatureUnknown,
	"PlainText": SignaturePlainText,
	"Encrypted": SignatureEncrypted,
	"Binary":    SignatureBinary,
	"_3nK":      Signature3nK,
}

var DataTypeIdFormat = map[string]uint32{
	"UTF8String":             DataTypeUTF8String,
	"ArrayOfUTF8String":      DataTypeArrayOfUTF8String,
	"EncodedString":          DataTypeEncodedString,
	"ArrayOfEncodedString":   DataTypeArrayOfEncodedString,
	"Single":                 DataTypeSingle,
	"ArrayOfSingle":          DataTypeArrayOfSingle,
	"VectorOf2Single":        DataTypeVectorOf2Single,
	"ArrayOfVectorOf2Single": DataTypeArrayOfVectorOf2Single,
	"VectorOf3Single":        DataTypeVectorOf3Single,
	"ArrayOfVectorOf3Single": DataTypeArrayOfVectorOf3Single,
	"VectorOf3Int32":         DataTypeVectorOf3Int32,
	"ArrayOfVectorOf3Int32":  DataTypeArrayOfVectorOf3Int32,
	"VectorOf4Single":        DataTypeVectorOf4Single,
	"ArrayOfVectorOf4Single": DataTypeArrayOfVectorOf4Single,
	"VectorOf8Single":        DataTypeVectorOf8Single,
	"ArrayOfVectorOf8Single": DataTypeArrayOfVectorOf8Single,
	"Int32":                  DataTypeInt32,
	"ArrayOfInt32":           DataTypeArrayOfInt32,
	"UInt32":                 DataTypeUInt32,
	"ArrayOfUInt32":          DataTypeArrayOfUInt32,
	"Int16":                  DataTypeInt16,
	"ArrayOfInt16":           DataTypeArrayOfInt16,
	"UInt16":                 DataTypeUInt16,
	"ArrayOfUInt16":          DataTypeArrayOfUInt16,
	"UInt32Type2":            DataTypeUInt32Type2,
	"Int64":                  DataTypeInt64,
	"ArrayOfInt64":           DataTypeArrayOfInt64,
	"UInt64":                 DataTypeUInt64,
	"ArrayOfUInt64":          DataTypeArrayOfUInt64,
	"ByteBool":               DataTypeByteBool,
	"ArrayOfByteBool":        DataTypeArrayOfByteBool,
	"OrdinalString":          DataTypeOrdinalString,
	"Id":                     DataTypeId,
	"ArrayOfIdA":             DataTypeArrayOfIdA,
	"IdType2":                DataTypeIdType2,
	"ArrayOfIdC":             DataTypeArrayOfIdC,
	"IdType3":                DataTypeIdType3,
	"ArrayOfIdE":             DataTypeArrayOfIdE,
}

type SingleVector2 struct {
	A float32
	B float32
}

type SingleVector3 struct {
	SingleVector2
	C float32
}

type SingleVector4 struct {
	SingleVector3
	D float32
}

type SingleVector7 struct {
	SingleVector4
	E float32
	F float32
	G float32
}

type SingleVector8 struct {
	SingleVector7
	H float32
}

type Int32Vector2 struct {
	A int32
	B int32
}

type Int32Vector3 struct {
	Int32Vector2
	C int32
}

type Int32Vector4 struct {
	Int32Vector3
	D int32
}

type Int32Vector7 struct {
	Int32Vector4
	E int32
	F int32
	G int32
}

type Int32Vector8 struct {
	Int32Vector7
	H int32
}

type IDComplexType struct {
	PartCount byte
	Address   uint64
	Value     *string
}

type BSIIHeader struct {
	Signature uint32
	Version   uint32
}

type SIIHeader struct {
	Signature uint32
	DataSize  int
}

type SIIData struct {
	Header           SIIHeader
	Data             []byte
	BinaryFormatInfo *BinaryFormatInfo
}

type BSIIDataSegment struct {
	Name  *string
	Type  uint32
	Value any
}

type BSIIStructureBlock struct {
	Type        uint32
	StructureID uint32
	Validity    bool
	Name        *string
	Segments    []BSIIDataSegment
	ID          *IDComplexType
}

type BSIIData struct {
	Header        BSIIHeader
	Blocks        []BSIIStructureBlock
	DecodedBlocks []BSIIStructureBlock
}

var BSIISupportedVersions = map[string]uint32{
	"Version1": BSIIVersion1,
	"Version2": BSIIVersion2,
	"Version3": BSIIVersion3,
}

// SIIDecryptResult defines the output of a file decryption process.
type SIIDecryptResult struct {
	Data             []byte            `json:"data"`
	StringContent    *string           `json:"string_content,omitempty"`
	Success          bool              `json:"success"`
	Type             string            `json:"type"` // Restricted values: "plain" | "encrypted" | "binary" | "3nK"
	Error            *string           `json:"error,omitempty"`
	Encrypted        bool              `json:"encrypted,omitempty"`
	BinaryFormatInfo *BinaryFormatInfo `json:"binaryFormatInfo,omitempty"`
}

// BinaryFormatInfo maps to your nested type configuration.
type BinaryFormatInfo struct {
	Header  *BSIIHeader `json:"header,omitempty"`
	Success *bool       `json:"success,omitempty"`
}

type SIIDecodeResult struct {
	Data    []byte
	Header  *BSIIHeader
	Success bool
	Error   *string
}
