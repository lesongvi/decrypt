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

package serializer

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"lsv.vn/go/sii_decrypt/internal/model"
)

var LIMITED_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"

func isUnsignedInteger(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isSignedInteger(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		if len(s) == 1 {
			return false
		}
		s = s[1:]
	}
	return isUnsignedInteger(s)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func Serialize(data model.BSIIData) []byte {
	var result strings.Builder
	result.Grow(64 + len(data.DecodedBlocks)*128)
	result.WriteString("SiiNunit\n{\n")

	for _, block := range data.DecodedBlocks {
		if block.Name == nil || block.ID == nil || block.ID.Value == nil {
			continue
		}

		result.WriteString(derefString(block.Name))
		result.WriteString(" : ")
		result.WriteString(derefString(block.ID.Value))
		result.WriteString(" {\n")

		for _, segment := range block.Segments {
			if segment.Type != 0 {
				result.WriteString(serializeSegment(segment, data.Header.Version))
			}
		}

		result.WriteString("}\n\n")
	}

	result.WriteString("}")
	return []byte(result.String())
}

func serializeSegment(segment model.BSIIDataSegment, version uint32) string {
	indent := " "
	name := derefString(segment.Name)

	switch segment.Type {
	case model.DataTypeArrayOfByteBool:
		return serializeByteBoolArray(segment, indent)

	case model.DataTypeArrayOfEncodedString:
		return serializeEncodedStringArray(segment, indent)

	case model.DataTypeArrayOfIdA,
		model.DataTypeArrayOfIdC,
		model.DataTypeArrayOfIdE:
		return serializeIDArray(segment, indent)

	case model.DataTypeArrayOfInt32:
		return serializeInt32Array(segment, indent)

	case model.DataTypeArrayOfSingle:
		return serializeSingleArray(segment, indent)

	case model.DataTypeArrayOfUInt16:
		return serializeUInt16Array(segment, indent)

	case model.DataTypeArrayOfUInt32:
		return serializeUInt32Array(segment, indent)

	case model.DataTypeArrayOfUInt64:
		return serializeUInt64Array(segment, indent)

	case model.DataTypeArrayOfUTF8String:
		return serializeUTF8StringArray(segment, indent)

	case model.DataTypeArrayOfVectorOf3Int32:
		return serializeInt32Vector3Array(segment, indent)

	case model.DataTypeArrayOfVectorOf3Single:
		return serializeSingleVector3Array(segment, indent)

	case model.DataTypeArrayOfVectorOf4Single:
		return serializeSingleVector4Array(segment, indent)

	case model.DataTypeArrayOfVectorOf8Single:
		if version == 1 {
			return serializeSingleVector7Array(segment, indent)
		}
		return serializeSingleVector8Array(segment, indent)

	case model.DataTypeByteBool:
		value := segment.Value.(bool)
		if value {
			return indent + name + ": true\n"
		}
		return indent + name + ": false\n"

	case model.DataTypeEncodedString:
		value := segment.Value.(string)
		if value == "" {
			value = `""`
		}
		return indent + name + ": " + value + "\n"

	case model.DataTypeIdType3,
		model.DataTypeIdType2,
		model.DataTypeId:
		idVal := ""
		switch value := segment.Value.(type) {
		case model.IDComplexType:
			idVal = derefString(value.Value)
		case *model.IDComplexType:
			if value != nil {
				idVal = derefString(value.Value)
			}
		default:
			panic(fmt.Sprintf("unexpected ID type: %T", segment.Value))
		}
		return indent + name + ": " + idVal + "\n"

	case model.DataTypeInt32:
		if segment.Value == nil {
			return indent + name + ": nil\n"
		}
		value := segment.Value.(int32)
		return indent + name + ": " + strconv.FormatInt(int64(value), 10) + "\n"

	case model.DataTypeInt64:
		return serializeInt64(segment, indent)

	case model.DataTypeUInt32Type2,
		model.DataTypeUInt32:
		value := segment.Value.(uint32)
		text := "nil"
		if value != math.MaxUint32 {
			text = strconv.FormatUint(uint64(value), 10)
		}
		return indent + name + ": " + text + "\n"

	case model.DataTypeUInt64:
		return serializeUInt64(segment, indent)

	case model.DataTypeUInt16:
		value := segment.Value.(uint16)
		text := "nil"
		if value != math.MaxUint16 {
			text = strconv.FormatUint(uint64(value), 10)
		}
		return indent + name + ": " + text + "\n"

	case model.DataTypeOrdinalString:
		value := segment.Value.(string)
		return indent + name + ": " + value + "\n"

	case model.DataTypeSingle:
		value := segment.Value.(float32)
		return indent + name + ": " + formatSingle(&value) + "\n"

	case model.DataTypeUTF8String:
		value := segment.Value.(string)
		output := indent + name + ": "

		switch {
		case isSignedInteger(value):
			output += value
		case value == "":
			output += `""`
		case strings.Contains(value, " "):
			output += `"` + value + `"`
		case isLimitedAlphabet(value):
			output += value
		default:
			output += `"` + value + `"`
		}

		return output + "\n"

	case model.DataTypeVectorOf2Single:
		return serializeSingleVector2(segment, indent)

	case model.DataTypeVectorOf3Int32:
		return serializeInt32Vector3(segment, indent)

	case model.DataTypeVectorOf3Single:
		return serializeSingleVector3(segment, indent)

	case model.DataTypeVectorOf4Single:
		return serializeSingleVector4(segment, indent)

	case model.DataTypeVectorOf8Single:
		if version == 1 {
			return serializeSingleVector7(segment, indent)
		}
		return serializeSingleVector8(segment, indent)

	case model.DataTypeArrayOfInt64:
		return serializeInt64Array(segment, indent)

	case model.DataTypeArrayOfInt16:
		return serializeInt16Array(segment, indent)

	case model.DataTypeInt16:
		return serializeInt16(segment, indent)

	case model.DataTypeArrayOfVectorOf2Single:
		return serializeSingleVector2Array(segment, indent)

	case 0:
		return ""

	default:
		panic(fmt.Sprintf(
			"unknown serialization type: %d for segment %s",
			segment.Type,
			derefString(segment.Name),
		))
	}
}

func formatSingle(value *float32) string {
	if value == nil {
		return "nil"
	}

	v := *value

	if v != float32(math.Trunc(float64(v))) || v >= 1e7 {
		bits := math.Float32bits(v)

		return fmt.Sprintf("&%02x%02x%02x%02x",
			byte(bits>>24),
			byte(bits>>16),
			byte(bits>>8),
			byte(bits),
		)
	}

	return strconv.FormatInt(int64(v), 10)
}

func isLimitedAlphabet(value string) bool {
	for _, ch := range value {
		if !strings.ContainsRune(LIMITED_ALPHABET, ch) {
			return false
		}
	}
	return true
}

func serializeByteBoolArray(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]bool)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %t\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeEncodedStringArray(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]string)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %s\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeIDArray(segment model.BSIIDataSegment, indent string) string {
	var result strings.Builder

	switch value := segment.Value.(type) {
	case []model.IDComplexType:
		result.WriteString(fmt.Sprintf("%s%s: %d\n",
			indent,
			derefString(segment.Name),
			len(value),
		))

		for i, v := range value {
			result.WriteString(fmt.Sprintf("%s%s[%d]: %s\n",
				indent,
				derefString(segment.Name),
				i,
				derefString(v.Value),
			))
		}

	case []*model.IDComplexType:
		result.WriteString(fmt.Sprintf("%s%s: %d\n",
			indent,
			derefString(segment.Name),
			len(value),
		))

		for i, v := range value {
			idVal := ""
			if v != nil {
				idVal = derefString(v.Value)
			}

			result.WriteString(fmt.Sprintf("%s%s[%d]: %s\n",
				indent,
				derefString(segment.Name),
				i,
				idVal,
			))
		}

	default:
		panic(fmt.Sprintf("unexpected ID array type: %T", segment.Value))
	}

	return result.String()
}

func serializeInt32Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]int32)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %d\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeSingleArray(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]float32)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %s\n",
			indent,
			derefString(segment.Name),
			i,
			formatSingle(&v),
		))
	}

	return result.String()
}

func serializeUInt16Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]uint16)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %d\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeUInt32Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]uint32)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %d\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeUInt64Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]uint64)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %d\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeInt32(segment model.BSIIDataSegment, indent string) string {
	if segment.Value == nil {
		return indent + derefString(segment.Name) + ": nil\n"
	}

	value := segment.Value.(int32)

	return indent + derefString(segment.Name) + ": " + strconv.FormatInt(int64(value), 10) + "\n"
}

func serializeUTF8String(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(string)

	output := indent + derefString(segment.Name) + ": "

	switch {
	case isSignedInteger(value):
		output += value

	case value == "":
		output += `""`

	case strings.Contains(value, " "):
		output += `"` + value + `"`

	case isLimitedAlphabet(value):
		output += value

	default:
		output += `"` + value + `"`
	}

	return output + "\n"
}

func serializeUTF8StringArray(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]string)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		switch {
		case isUnsignedInteger(v):
			result.WriteString(fmt.Sprintf("%s%s[%d]: %s\n",
				indent, derefString(segment.Name), i, v))

		case v == "":
			result.WriteString(fmt.Sprintf("%s%s[%d]: \"\"\n",
				indent, derefString(segment.Name), i))

		case isLimitedAlphabet(v):
			result.WriteString(fmt.Sprintf("%s%s[%d]: %s\n",
				indent, derefString(segment.Name), i, v))

		default:
			result.WriteString(fmt.Sprintf("%s%s[%d]: \"%s\"\n",
				indent, derefString(segment.Name), i, v))
		}
	}

	return result.String()
}

func serializeInt32Vector3Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]model.Int32Vector3)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: (%d, %d, %d)\n",
			indent,
			derefString(segment.Name),
			i,
			v.A,
			v.B,
			v.C,
		))
	}

	return result.String()
}

func serializeSingleVector3Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]model.SingleVector3)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: (%s, %s, %s)\n",
			indent,
			derefString(segment.Name),
			i,
			formatSingle(&v.A),
			formatSingle(&v.B),
			formatSingle(&v.C),
		))
	}

	return result.String()
}

func serializeSingleVector2Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]model.SingleVector2)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: (%s, %s)\n",
			indent,
			derefString(segment.Name),
			i,
			formatSingle(&v.A),
			formatSingle(&v.B),
		))
	}

	return result.String()
}

func serializeSingleVector4Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]model.SingleVector4)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: (%s; %s, %s, %s)\n",
			indent,
			derefString(segment.Name),
			i,
			formatSingle(&v.A),
			formatSingle(&v.B),
			formatSingle(&v.C),
			formatSingle(&v.D),
		))
	}

	return result.String()
}

func serializeSingleVector8Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]model.SingleVector8)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf(
			"%s%s[%d]: (%s, %s, %s) (%s; %s, %s, %s)\n",
			indent,
			derefString(segment.Name),
			i,
			formatSingle(&v.A),
			formatSingle(&v.B),
			formatSingle(&v.C),
			formatSingle(&v.E),
			formatSingle(&v.F),
			formatSingle(&v.G),
			formatSingle(&v.H),
		))
	}

	return result.String()
}

func serializeSingleVector7Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]model.SingleVector7)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf(
			"%s%s[%d]: (%s, %s, %s) (%s; %s, %s, %s)\n",
			indent,
			derefString(segment.Name),
			i,
			formatSingle(&v.A),
			formatSingle(&v.B),
			formatSingle(&v.C),
			formatSingle(&v.D),
			formatSingle(&v.E),
			formatSingle(&v.F),
			formatSingle(&v.G),
		))
	}

	return result.String()
}

func serializeBool(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(bool)
	if value {
		return indent + derefString(segment.Name) + ": true\n"
	}
	return indent + derefString(segment.Name) + ": false\n"
}

func serializeEncodedString(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(string)

	if value == "" {
		value = `""`
	}

	return indent + derefString(segment.Name) + ": " + value + "\n"
}

func serializeId(segment model.BSIIDataSegment, indent string) string {
	idVal := ""
	switch value := segment.Value.(type) {
	case model.IDComplexType:
		idVal = derefString(value.Value)
	case *model.IDComplexType:
		if value != nil {
			idVal = derefString(value.Value)
		}
	default:
		panic(fmt.Sprintf("unexpected ID type: %T", segment.Value))
	}

	return indent + derefString(segment.Name) + ": " + idVal + "\n"
}

func serializeInt64(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(int64)
	return indent + derefString(segment.Name) + ": " + strconv.FormatInt(value, 10) + "\n"
}

func serializeUInt32(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(uint32)

	text := "nil"
	if value != math.MaxUint32 {
		text = strconv.FormatUint(uint64(value), 10)
	}

	return indent + derefString(segment.Name) + ": " + text + "\n"
}

func serializeUInt64(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(uint64)
	return indent + derefString(segment.Name) + ": " + strconv.FormatUint(value, 10) + "\n"
}

func serializeUInt16(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(uint16)

	text := "nil"
	if value != math.MaxUint16 {
		text = strconv.FormatUint(uint64(value), 10)
	}

	return indent + derefString(segment.Name) + ": " + text + "\n"
}

func serializeOrdinalString(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(string)
	return indent + derefString(segment.Name) + ": " + value + "\n"
}

func serializeInt16Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]int16)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %d\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeInt16(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(int16)

	text := "nil"
	if value != math.MaxInt16 {
		text = strconv.FormatInt(int64(value), 10)
	}

	return indent + derefString(segment.Name) + ": " + text + "\n"
}

func serializeSingleVector2(segment model.BSIIDataSegment, indent string) string {
	vector := segment.Value.(model.SingleVector2)

	return fmt.Sprintf("%s%s: (%s, %s)\n",
		indent,
		derefString(segment.Name),
		formatSingle(&vector.A),
		formatSingle(&vector.B),
	)
}

func serializeInt32Vector3(segment model.BSIIDataSegment, indent string) string {
	vector := segment.Value.(model.Int32Vector3)

	return fmt.Sprintf("%s%s: (%d, %d, %d)\n",
		indent,
		derefString(segment.Name),
		vector.A,
		vector.B,
		vector.C,
	)
}

func serializeSingleVector3(segment model.BSIIDataSegment, indent string) string {
	vector := segment.Value.(model.SingleVector3)

	return indent + derefString(segment.Name) + ": (" +
		formatSingle(&vector.A) + ", " +
		formatSingle(&vector.B) + ", " +
		formatSingle(&vector.C) + ")\n"
}

func serializeSingleVector4(segment model.BSIIDataSegment, indent string) string {
	vector := segment.Value.(model.SingleVector4)

	return fmt.Sprintf("%s%s: (%s; %s, %s, %s)\n",
		indent,
		derefString(segment.Name),
		formatSingle(&vector.A),
		formatSingle(&vector.B),
		formatSingle(&vector.C),
		formatSingle(&vector.D),
	)
}

func serializeSingleVector8(segment model.BSIIDataSegment, indent string) string {
	vector := segment.Value.(model.SingleVector8)

	return fmt.Sprintf(
		"%s%s: (%s, %s, %s) (%s; %s, %s, %s)\n",
		indent,
		derefString(segment.Name),
		formatSingle(&vector.A),
		formatSingle(&vector.B),
		formatSingle(&vector.C),
		formatSingle(&vector.E),
		formatSingle(&vector.F),
		formatSingle(&vector.G),
		formatSingle(&vector.H),
	)
}

func serializeSingleVector7(segment model.BSIIDataSegment, indent string) string {
	vector := segment.Value.(model.SingleVector7)

	return fmt.Sprintf(
		"%s%s: (%s, %s, %s) (%s; %s, %s, %s)\n",
		indent,
		derefString(segment.Name),
		formatSingle(&vector.A),
		formatSingle(&vector.B),
		formatSingle(&vector.C),
		formatSingle(&vector.D),
		formatSingle(&vector.E),
		formatSingle(&vector.F),
		formatSingle(&vector.G),
	)
}

func serializeInt64Array(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.([]int64)

	var result strings.Builder

	result.WriteString(fmt.Sprintf("%s%s: %d\n",
		indent,
		derefString(segment.Name),
		len(value),
	))

	for i, v := range value {
		result.WriteString(fmt.Sprintf("%s%s[%d]: %d\n",
			indent,
			derefString(segment.Name),
			i,
			v,
		))
	}

	return result.String()
}

func serializeSingle(segment model.BSIIDataSegment, indent string) string {
	value := segment.Value.(float32)
	return indent + derefString(segment.Name) + ": " + formatSingle(&value) + "\n"
}
