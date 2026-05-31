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

package decoder

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"lsv.vn/go/sii_decrypt/internal/model"
)

const CharTable = "0123456789abcdefghijklmnopqrstuvwxyz_"

// 0x35
func DecodeBool(bytes []byte, offset *int) bool {
	result := bytes[*offset] != 0
	*offset++
	return result
}

// 0x09
func DecodeSingleVector3(bytes []byte, offset *int) model.SingleVector3 {
	return model.SingleVector3{
		SingleVector2: model.SingleVector2{
			A: DecodeSingle(bytes, offset), // Decodes X/A component (4 bytes)
			B: DecodeSingle(bytes, offset), // Decodes Y/B component (4 bytes)
		},
		C: DecodeSingle(bytes, offset), // Decodes Z/C component (4 bytes)
	}
}

// 0x0A
func DecodeSingleVector3Array(bytes []byte, offset *int) []model.SingleVector3 {
	// 1. Decode the total number of vectors in the array
	numberOfVector3s := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]model.SingleVector3, numberOfVector3s)

	// 3. Loop through and assign each decoded vector directly
	for i := 0; i < numberOfVector3s; i++ {
		result[i] = DecodeSingleVector3(bytes, offset)
	}

	return result
}

// 0x17
func DecodeSingleVector4(bytes []byte, offset *int) model.SingleVector4 {
	return model.SingleVector4{
		SingleVector3: model.SingleVector3{
			SingleVector2: model.SingleVector2{
				A: DecodeSingle(bytes, offset), // Decodes A component (4 bytes)
				B: DecodeSingle(bytes, offset), // Decodes B component (4 bytes)
			},
			C: DecodeSingle(bytes, offset), // Decodes C component (4 bytes)
		},
		D: DecodeSingle(bytes, offset), // Decodes D component (4 bytes)
	}
}

// 0x18
func DecodeSingleVector4Array(bytes []byte, offset *int) []model.SingleVector4 {
	// 1. Decode the total number of vectors in the array
	number := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]model.SingleVector4, number)

	// 3. Loop through and assign each decoded vector directly
	for i := 0; i < number; i++ {
		result[i] = DecodeSingleVector4(bytes, offset)
	}

	return result
}

// 0x19
func DecodeSingleVector7(bytes []byte, offset *int) model.SingleVector7 {
	return model.SingleVector7{
		SingleVector4: model.SingleVector4{
			SingleVector3: model.SingleVector3{
				SingleVector2: model.SingleVector2{
					A: DecodeSingle(bytes, offset), // Decodes 1st (4 bytes)
					B: DecodeSingle(bytes, offset), // Decodes 2nd (4 bytes)
				},
				C: DecodeSingle(bytes, offset), // Decodes 3rd (4 bytes)
			},
			D: DecodeSingle(bytes, offset), // Decodes 4th (4 bytes)
		},
		E: DecodeSingle(bytes, offset), // Decodes 5th (4 bytes)
		F: DecodeSingle(bytes, offset), // Decodes 6th (4 bytes)
		G: 0.0,                         // Hardcoded default fallback
	}
}

// 0x1A
func DecodeSingleVector7Array(bytes []byte, offset *int) []model.SingleVector7 {
	// 1. Decode the total number of vectors in the array
	numberOfVector7s := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]model.SingleVector7, numberOfVector7s)

	// 3. Loop through and assign each decoded vector directly
	for i := 0; i < numberOfVector7s; i++ {
		result[i] = DecodeSingleVector7(bytes, offset)
	}

	return result
}

// DecodeSingleVector8 decodes an 8D vector and applies bit-packing adjustments
// from component D to modify components A and C.
func DecodeSingleVector8(bytes []byte, offset *int) model.SingleVector8 {
	var result model.SingleVector8

	// 1. Sequentially decode components from the byte stream
	result.SingleVector7.SingleVector4.SingleVector3.SingleVector2.A = DecodeSingle(bytes, offset)
	result.SingleVector7.SingleVector4.SingleVector3.SingleVector2.B = DecodeSingle(bytes, offset)
	result.SingleVector7.SingleVector4.SingleVector3.C = DecodeSingle(bytes, offset)
	result.SingleVector7.SingleVector4.D = DecodeSingle(bytes, offset)
	result.SingleVector7.E = DecodeSingle(bytes, offset)
	result.SingleVector7.F = DecodeSingle(bytes, offset)
	result.SingleVector7.G = DecodeSingle(bytes, offset)
	result.H = DecodeSingle(bytes, offset)

	// 2. Perform Math.floor and cast to uint64 for bit manipulation
	bias := uint64(math.Floor(float64(result.SingleVector7.SingleVector4.D)))

	// 3. Process adjustments for component A
	bits := bias & 0xFFF
	bits -= 2048
	bits = bits << 9
	result.SingleVector7.SingleVector4.SingleVector3.SingleVector2.A += float32(int64(bits))

	// 4. Process adjustments for component C
	bits2 := bias >> 12
	bits2 &= 0xFFF
	bits2 -= 2048
	bits2 = bits2 << 9
	result.SingleVector7.SingleVector4.SingleVector3.C += float32(int64(bits2))

	return result
}

func DecodeSingleVector8Array(bytes []byte, offset *int) []model.SingleVector8 {
	// 1. Decode the total number of vectors in the array
	numberOfVector8s := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]model.SingleVector8, numberOfVector8s)

	// 3. Loop through and assign each decoded vector directly
	for i := 0; i < numberOfVector8s; i++ {
		result[i] = DecodeSingleVector8(bytes, offset)
	}

	return result
}

// 0x29
func DecodeInt16(bytes []byte, offset *int) int16 {
	// 1. Read the 2 bytes as a uint16 using Little Endian, then cast to int16
	result := int16(binary.LittleEndian.Uint16(bytes[*offset : *offset+2]))

	// 2. Advance the offset value by 2 bytes
	*offset += 2

	return result
}

// 0x2A
func DecodeInt16Array(bytes []byte, offset *int) []int16 {
	// 1. Decode the total number of integers in the array
	numberOfInts := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]int16, numberOfInts)

	// 3. Loop through and assign each decoded int16 directly
	for i := 0; i < numberOfInts; i++ {
		result[i] = DecodeInt16(bytes, offset)
	}

	return result
}

// 0x07
func DecodeSingleVector2(bytes []byte, offset *int) model.SingleVector2 {
	return model.SingleVector2{
		A: DecodeSingle(bytes, offset), // Decodes X/A component (4 bytes)
		B: DecodeSingle(bytes, offset), // Decodes Y/B component (4 bytes)
	}
}

// 0x08
func DecodeSingleVector2Array(bytes []byte, offset *int) []model.SingleVector2 {
	// 1. Decode the total number of vectors in the array
	numberOfVector2s := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]model.SingleVector2, numberOfVector2s)

	// 3. Loop through and assign each decoded vector directly
	for i := 0; i < numberOfVector2s; i++ {
		result[i] = DecodeSingleVector2(bytes, offset)
	}

	return result
}

// 0x25
func DecodeInt32(bytes []byte, offset *int) int32 {
	// 1. Read the 4 bytes as a uint32 using Little Endian, then cast to int32
	result := int32(binary.LittleEndian.Uint32(bytes[*offset : *offset+4]))

	// 2. Advance the offset value by 4 bytes
	*offset += 4

	return result
}

// 0x26
func DecodeInt32Array(bytes []byte, offset *int) []int32 {
	// 1. Decode the total number of integers in the array
	numberOfInts := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]int32, numberOfInts)

	// 3. Loop through and assign each decoded int32 directly
	for i := 0; i < numberOfInts; i++ {
		result[i] = DecodeInt32(bytes, offset)
	}

	return result
}

// 0x05
func DecodeSingle(bytes []byte, offset *int) float32 {
	// 1. Read the 4 bytes as bits (uint32) using Little Endian
	bits := binary.LittleEndian.Uint32(bytes[*offset : *offset+4])

	// 2. Reinterpret those bits as an IEEE 754 float32
	result := math.Float32frombits(bits)

	// 3. Advance the offset value by 4 bytes
	*offset += 4

	return result
}

// 0x06
func DecodeSingleArray(bytes []byte, offset *int) []float32 {
	// 1. Decode the total number of single floats in the array
	numberOfSingles := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]float32, numberOfSingles)

	// 3. Loop through and assign each decoded float32 directly
	for i := 0; i < numberOfSingles; i++ {
		result[i] = DecodeSingle(bytes, offset)
	}

	return result
}

// 0x03
func DecodeUInt64String(bytes []byte, offset *int) string {
	result := ""
	value := DecodeUInt64(bytes, offset)

	for value != 0 {
		charIdx := int(value % 38)

		// In Go, since 'value' is a uint64 (unsigned), charIdx will always be >= 0.
		// We can directly subtract 1.
		charIdx -= 1
		value = value / 38

		if charIdx > -1 && charIdx < 38 {
			result += string(CharTable[charIdx])
		}
	}

	return result
}

// 0x2B
func DecodeUInt16(bytes []byte, offset *int) uint16 {
	// 1. Read the 2 bytes as a uint16 using Little Endian
	result := binary.LittleEndian.Uint16(bytes[*offset : *offset+2])

	// 2. Advance the offset value by 2 bytes
	*offset += 2

	return result
}

// 0x27 and 0x2F
func DecodeUInt32(bytes []byte, offset *int) uint32 {
	// 1. Read the 4 bytes as a uint32 using Little Endian
	result := binary.LittleEndian.Uint32(bytes[*offset : *offset+4])

	// 2. Advance the offset value by 4 bytes
	*offset += 4

	return result
}

// 0x28
func DecodeUInt32Array(bytes []byte, offset *int) []uint32 {
	// 1. Decode the total number of integers in the array
	numberOfInts := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]uint32, numberOfInts)

	// 3. Loop through and assign each decoded uint32 directly
	for i := 0; i < numberOfInts; i++ {
		result[i] = DecodeUInt32(bytes, offset)
	}

	return result
}

// 0x31
func DecodeInt64(bytes []byte, offset *int) int64 {
	// 1. Read the 8 bytes as a uint64 using Little Endian, then cast to int64
	result := int64(binary.LittleEndian.Uint64(bytes[*offset : *offset+8]))

	// 2. Advance the offset value by 8 bytes
	*offset += 8

	return result
}

// 0x32
func DecodeInt64Array(bytes []byte, offset *int) []int64 {
	// 1. Decode the total number of integers in the array
	numberOfInts := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]int64, numberOfInts)

	// 3. Loop through and assign each decoded int64 directly
	for i := 0; i < numberOfInts; i++ {
		result[i] = DecodeInt64(bytes, offset)
	}

	return result
}

// 0x33
func DecodeUInt64(bytes []byte, offset *int) uint64 {
	// 1. Read the 8 bytes as a uint64 using Little Endian
	result := binary.LittleEndian.Uint64(bytes[*offset : *offset+8])

	// 2. Advance the offset value by 8 bytes
	*offset += 8

	return result
}

// 0x34
func DecodeUInt64Array(bytes []byte, offset *int) []uint64 {
	// 1. Decode the total number of integers in the array
	numberOfInts := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]uint64, numberOfInts)

	// 3. Loop through and assign each decoded uint64 directly
	for i := 0; i < numberOfInts; i++ {
		result[i] = DecodeUInt64(bytes, offset)
	}

	return result
}

// 0x2C
func DecodeUInt16Array(bytes []byte, offset *int) []uint16 {
	// 1. Decode the total number of integers in the array
	numberOfInts := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]uint16, numberOfInts)

	// 3. Loop through and assign each decoded uint16 directly
	for i := 0; i < numberOfInts; i++ {
		result[i] = DecodeUInt16(bytes, offset)
	}

	return result
}

// 0x04
func DecodeUInt64StringArray(bytes []byte, offset *int) []string {
	// 1. Decode the total number of strings in the array
	numberOfStrings := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]string, numberOfStrings)

	// 3. Loop through and assign each decoded string directly
	for i := 0; i < numberOfStrings; i++ {
		result[i] = DecodeUInt64String(bytes, offset)
	}

	return result
}

// 0x01
func DecodeUTF8String(bytes []byte, offset *int) *string {
	// 1. Decode the length of the string
	length := int(DecodeUInt32(bytes, offset))

	// 2. Slice the bytes for the string using the updated offset
	start := *offset
	end := start + length
	result := string(bytes[start:end])

	// 3. Advance the offset by the length of the string
	*offset += length

	return &result
}

// 0x02
func DecodeUTF8StringArray(bytes []byte, offset *int) []string {
	// 1. Decode the total number of strings in the array
	numberOfStrings := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]string, numberOfStrings)

	// 3. Loop through and assign each decoded string directly
	for i := 0; i < numberOfStrings; i++ {
		result[i] = *DecodeUTF8String(bytes, offset)
	}

	return result
}

// 0x11
func DecodeInt32Vector3(bytes []byte, offset *int) model.Int32Vector3 {
	return model.Int32Vector3{
		Int32Vector2: model.Int32Vector2{
			A: DecodeInt32(bytes, offset),
			B: DecodeInt32(bytes, offset),
		},
		C: DecodeInt32(bytes, offset),
	}
}

// 0x12
func DecodeInt32Vector3Array(bytes []byte, offset *int) []model.Int32Vector3 {
	// 1. Decode the total number of vectors in the array
	numberOfVector3s := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]model.Int32Vector3, numberOfVector3s)

	// 3. Loop through and assign each decoded vector directly
	for i := 0; i < numberOfVector3s; i++ {
		result[i] = DecodeInt32Vector3(bytes, offset)
	}

	return result
}

// 0x37
func DecodeOrdinalStringList(bytes []byte, offset *int) map[uint32]*string {
	// 1. Read the number of items in the list/map
	length := int(DecodeUInt32(bytes, offset))

	// 2. Initialize the map with a capacity hint for performance
	values := make(map[uint32]*string, length)

	// 3. Loop through and populate the map
	for i := 0; i < length; i++ {
		ordinal := DecodeUInt32(bytes, offset)
		stringValue := DecodeUTF8String(bytes, offset)

		values[ordinal] = stringValue
	}

	return values
}

func GetOrdinalStringFromValues(values map[uint32]*string, bytes []byte, offset *int) string {
	// 1. Decode the map key index from the binary stream
	index := DecodeUInt32(bytes, offset)

	// 2. Look up the index value. If found and non-nil, return dereferenced string.
	str, ok := values[index]
	if !ok || str == nil {
		return ""
	}

	return *str
}

// 0x39, 0x3B, 0x3D
func DecodeID(bytes []byte, offset *int) *model.IDComplexType {
	var result model.IDComplexType
	initialValue := ""
	result.Value = &initialValue

	// Read individual byte for part count
	result.PartCount = bytes[*offset]
	*offset += 1

	if result.PartCount == 0xFF {
		result.Address = DecodeUInt64(bytes, offset)

		// Create 8 bytes on the stack and write using Little Endian
		var data [8]byte
		binary.LittleEndian.PutUint64(data[:], result.Address)

		parts := make([]string, len(data)/2)
		currentPart := ""

		for i := 0; i < len(data); i++ {
			if i%2 == 0 && i > 0 {
				if i >= len(data)-2 {
					// Emulate: while(currentPart.startsWith("0")) currentPart = currentPart.substring(1)
					currentPart = strings.TrimLeft(currentPart, "0")
				}

				if currentPart != "" {
					strRes := currentPart + "." + *(result.Value)
					result.Value = &strRes
				}

				parts[(len(data)/2)-(i/2)] = currentPart
				currentPart = ""
			}

			// Format byte to hex string padding to 2 digits
			currentPart = fmt.Sprintf("%02x", data[i]) + currentPart

			if i == len(data)-1 {
				currentPart = strings.TrimLeft(currentPart, "0")
				if currentPart != "" {
					strRes := currentPart + "." + *(result.Value)
					result.Value = &strRes
				}
				parts[0] = currentPart
			}
		}

		if len(*(result.Value)) > 0 {
			strRes := "_nameless." + (*result.Value)[:len(*result.Value)-1]
			result.Value = &strRes
		} else {
			strRes := "_nameless."
			result.Value = &strRes
		}

	} else {
		for i := 0; i < int(result.PartCount); i++ {
			s := DecodeUInt64String(bytes, offset)

			if i > 0 {
				strRes := fmt.Sprintf("%s%s", *result.Value, ".")
				result.Value = &strRes

			}
			strResz := fmt.Sprintf("%s%s", *result.Value, s)
			result.Value = &strResz

		}
		if result.PartCount == 0 {
			strRes := "null"
			result.Value = &strRes
		}
	}

	return &result
}

// 0x36
func DecodeBoolArray(bytes []byte, offset *int) []bool {
	// 1. Decode the total number of booleans in the array
	numberOfBools := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]bool, numberOfBools)

	// 3. Loop through and assign each decoded boolean directly
	for i := 0; i < numberOfBools; i++ {
		result[i] = DecodeBool(bytes, offset)
	}

	return result
}

// 0x3A, 0x3C, 0x3E
func DecodeIDArray(bytes []byte, offset *int) []*model.IDComplexType {
	// 1. Decode the total number of IDs in the array
	numberOfIds := int(DecodeUInt32(bytes, offset))

	// 2. Pre-allocate the slice capacity to optimize memory allocations
	result := make([]*model.IDComplexType, numberOfIds)

	// 3. Loop through and assign each decoded ID directly
	for i := 0; i < numberOfIds; i++ {
		result[i] = DecodeID(bytes, offset)
	}

	return result
}
