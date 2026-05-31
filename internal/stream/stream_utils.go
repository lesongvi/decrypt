package stream

import "encoding/binary"

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

func TryReadUInt32(bytes []byte, offset *int) (uint32, bool) {
	// 1. Explicitly check if there are at least 4 bytes available to read
	if *offset+4 <= len(bytes) {
		// 2. Read the 32-bit unsigned integer using Little Endian
		result := binary.LittleEndian.Uint32(bytes[*offset : *offset+4])

		// 3. Advance the offset
		*offset += 4

		return result, true
	}

	// Return the zero value and false if out of bounds
	return 0, false
}
