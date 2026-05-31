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

package bsii

import (
	"fmt"
	"log"

	"lsv.vn/go/sii_decrypt/internal/bsii/decoder"
	"lsv.vn/go/sii_decrypt/internal/bsii/serializer"
	"lsv.vn/go/sii_decrypt/internal/model"
)

func Decode(bytes []byte) (*model.SIIDecodeResult, error) {
	result := &model.SIIDecodeResult{
		Data:    []byte{},
		Success: false,
	}

	streamPos := 0

	fileData := model.BSIIData{
		Header: model.BSIIHeader{
			Signature: 0,
			Version:   0,
		},
		Blocks:        []model.BSIIStructureBlock{},
		DecodedBlocks: []model.BSIIStructureBlock{},
	}

	fileData.Header.Signature = decoder.DecodeUInt32(bytes, &streamPos)
	fileData.Header.Version = decoder.DecodeUInt32(bytes, &streamPos)

	switch fileData.Header.Version {
	case model.BSIIVersion1, model.BSIIVersion2, model.BSIIVersion3:
	default:
		return nil, fmt.Errorf("BSII version not supported")
	}

	result.Header = &fileData.Header

	var blockType uint32

	ordinalLists := make(map[uint32]map[uint32]*string)
	structureIndex := make(map[uint32]int)

	for streamPos < len(bytes) {
		blockType = decoder.DecodeUInt32(bytes, &streamPos)

		if blockType == 0 {
			name := ""
			currentBlock := model.BSIIStructureBlock{
				Type:        blockType,
				StructureID: 0,
				Validity:    false,
				Name:        &name,
				Segments:    []model.BSIIDataSegment{},
			}

			currentBlock.Validity = decoder.DecodeBool(bytes, &streamPos)

			if !currentBlock.Validity {
				fileData.Blocks = append(fileData.Blocks, currentBlock)
				continue
			}

			currentBlock.StructureID = decoder.DecodeUInt32(bytes, &streamPos)
			currentBlock.Name = decoder.DecodeUTF8String(bytes, &streamPos)

			segment := model.BSIIDataSegment{
				Name:  &name,
				Type:  999,
				Value: nil,
			}

			for segment.Type != 0 {
				segment = readDataBlock(bytes, &streamPos)

				if segment.Type == model.DataTypeOrdinalString {
					if _, exists := ordinalLists[currentBlock.StructureID]; !exists {
						ordinalLists[currentBlock.StructureID] =
							segment.Value.(map[uint32]*string)
					}
				}

				currentBlock.Segments = append(currentBlock.Segments, segment)
			}

			if _, exists := structureIndex[currentBlock.StructureID]; !exists {
				structureIndex[currentBlock.StructureID] = len(fileData.Blocks)
				fileData.Blocks = append(fileData.Blocks, currentBlock)
			}
		} else {
			blockIndex, ok := structureIndex[blockType]
			if !ok {
				continue
			}
			blockDataItem := &fileData.Blocks[blockIndex]

			blockData := model.BSIIStructureBlock{
				StructureID: blockDataItem.StructureID,
				Name:        blockDataItem.Name,
				Type:        blockDataItem.Type,
				Validity:    blockDataItem.Validity,
				Segments:    make([]model.BSIIDataSegment, len(blockDataItem.Segments)),
			}

			for i, segment := range blockDataItem.Segments {
				blockData.Segments[i] = model.BSIIDataSegment{
					Name:  segment.Name,
					Type:  segment.Type,
					Value: segment.Value,
				}
			}

			if blockDataItem.ID != nil {
				blockData.ID = &model.IDComplexType{
					Address:   blockDataItem.ID.Address,
					PartCount: blockDataItem.ID.PartCount,
					Value:     blockDataItem.ID.Value,
				}
			}

			list := ordinalLists[blockData.StructureID]
			if list == nil {
				list = make(map[uint32]*string)
			}

			loadDataBlockLocal(
				bytes,
				&streamPos,
				&blockData,
				fileData.Header.Version,
				list,
			)

			fileData.DecodedBlocks = append(
				fileData.DecodedBlocks,
				blockData,
			)
		}
	}

	result.Data = serializer.Serialize(fileData)
	result.Success = true

	return result, nil
}

func loadDataBlockLocal(
	bytes []byte,
	streamPos *int,
	segment *model.BSIIStructureBlock,
	formatVersion uint32,
	values map[uint32]*string,
) bool {
	segment.ID = decoder.DecodeID(bytes, streamPos)

	for i := 0; i < len(segment.Segments); i++ {
		dataType := segment.Segments[i].Type

		switch dataType {
		case model.DataTypeArrayOfByteBool:
			segment.Segments[i].Value = decoder.DecodeBoolArray(bytes, streamPos)

		case model.DataTypeArrayOfEncodedString:
			segment.Segments[i].Value = decoder.DecodeUInt64StringArray(bytes, streamPos)

		case model.DataTypeArrayOfIdA, model.DataTypeArrayOfIdC, model.DataTypeArrayOfIdE:
			segment.Segments[i].Value = decoder.DecodeIDArray(bytes, streamPos)

		case model.DataTypeArrayOfInt32:
			segment.Segments[i].Value = decoder.DecodeInt32Array(bytes, streamPos)

		case model.DataTypeArrayOfSingle:
			segment.Segments[i].Value = decoder.DecodeSingleArray(bytes, streamPos)

		case model.DataTypeArrayOfUInt16:
			segment.Segments[i].Value = decoder.DecodeUInt16Array(bytes, streamPos)

		case model.DataTypeArrayOfUInt32:
			segment.Segments[i].Value = decoder.DecodeUInt32Array(bytes, streamPos)

		case model.DataTypeArrayOfUInt64:
			segment.Segments[i].Value = decoder.DecodeUInt64Array(bytes, streamPos)

		case model.DataTypeArrayOfUTF8String:
			segment.Segments[i].Value = decoder.DecodeUTF8StringArray(bytes, streamPos)

		case model.DataTypeArrayOfVectorOf3Int32:
			segment.Segments[i].Value = decoder.DecodeInt32Vector3Array(bytes, streamPos)

		case model.DataTypeArrayOfVectorOf3Single:
			segment.Segments[i].Value = decoder.DecodeSingleVector3Array(bytes, streamPos)

		case model.DataTypeArrayOfVectorOf4Single:
			segment.Segments[i].Value = decoder.DecodeSingleVector4Array(bytes, streamPos)

		case model.DataTypeArrayOfVectorOf8Single:
			if formatVersion == 1 {
				segment.Segments[i].Value = decoder.DecodeSingleVector7Array(bytes, streamPos)
			} else {
				segment.Segments[i].Value = decoder.DecodeSingleVector8Array(bytes, streamPos)
			}

		case model.DataTypeByteBool:
			segment.Segments[i].Value = decoder.DecodeBool(bytes, streamPos)

		case model.DataTypeEncodedString:
			segment.Segments[i].Value = decoder.DecodeUInt64String(bytes, streamPos)

		case model.DataTypeIdType3, model.DataTypeIdType2, model.DataTypeId:
			segment.Segments[i].Value = decoder.DecodeID(bytes, streamPos)

		case model.DataTypeInt32:
			segment.Segments[i].Value = decoder.DecodeInt32(bytes, streamPos)

		case model.DataTypeInt64:
			segment.Segments[i].Value = decoder.DecodeInt64(bytes, streamPos)

		case model.DataTypeUInt32Type2, model.DataTypeUInt32:
			segment.Segments[i].Value = decoder.DecodeUInt32(bytes, streamPos)

		case model.DataTypeUInt64:
			segment.Segments[i].Value = decoder.DecodeUInt64(bytes, streamPos)

		case model.DataTypeUInt16:
			segment.Segments[i].Value = decoder.DecodeUInt16(bytes, streamPos)

		case model.DataTypeOrdinalString:
			segment.Segments[i].Value = decoder.GetOrdinalStringFromValues(values, bytes, streamPos)

		case model.DataTypeSingle:
			segment.Segments[i].Value = decoder.DecodeSingle(bytes, streamPos)

		case model.DataTypeUTF8String:
			str := decoder.DecodeUTF8String(bytes, streamPos)
			if str == nil {
				segment.Segments[i].Value = ""
			} else {
				segment.Segments[i].Value = *str
			}

		case model.DataTypeVectorOf2Single:
			segment.Segments[i].Value = decoder.DecodeSingleVector2(bytes, streamPos)

		case model.DataTypeVectorOf3Int32:
			segment.Segments[i].Value = decoder.DecodeInt32Vector3(bytes, streamPos)

		case model.DataTypeVectorOf3Single:
			segment.Segments[i].Value = decoder.DecodeSingleVector3(bytes, streamPos)

		case model.DataTypeVectorOf4Single:
			segment.Segments[i].Value = decoder.DecodeSingleVector4(bytes, streamPos)

		case model.DataTypeVectorOf8Single:
			if formatVersion == 1 {
				segment.Segments[i].Value = decoder.DecodeSingleVector7(bytes, streamPos)
			} else {
				segment.Segments[i].Value = decoder.DecodeSingleVector8(bytes, streamPos)
			}

		case model.DataTypeArrayOfInt64:
			segment.Segments[i].Value = decoder.DecodeInt64Array(bytes, streamPos)

		case model.DataTypeArrayOfInt16:
			segment.Segments[i].Value = decoder.DecodeInt16Array(bytes, streamPos)

		case model.DataTypeInt16:
			segment.Segments[i].Value = decoder.DecodeInt16(bytes, streamPos)

		case model.DataTypeArrayOfVectorOf2Single:
			segment.Segments[i].Value = decoder.DecodeSingleVector2Array(bytes, streamPos)

		case 0:
			continue

		default:
			log.Printf("UNKNOWN TYPE: %d\n", dataType)
		}
	}

	return true
}

func readDataBlock(bytes []byte, streamPos *int) model.BSIIDataSegment {
	var result model.BSIIDataSegment

	// 1. decoder.Decode the type
	result.Type = decoder.DecodeUInt32(bytes, streamPos)

	// 2. If type is not 0, decode the name
	if result.Type != 0 {
		result.Name = decoder.DecodeUTF8String(bytes, streamPos)
	}

	// 3. If type matches OrdinalString, decode the value list
	if result.Type == model.DataTypeOrdinalString {
		result.Value = decoder.DecodeOrdinalStringList(bytes, streamPos)
	}

	return result
}
