package codecs

import (
	"encoding/binary"
	"fmt"
)

// H264Payloader payloads H264 packets
type H264Payloader struct{}

const (
	stapaNALUType = 24
	stapbNALUType = 25
	fuaNALUType   = 28
	fubNALUType   = 29

	fuaHeaderSize       = 2
	fubHeaderSize       = 2
	stapaHeaderSize     = 1
	stapbHeaderSize     = 1

	stapaNALULengthSize = 2
	stapbNALULengthSize = 2

	donSize = 2

	naluTypeBitmask   = 0x1F
	naluRefIdcBitmask = 0x60
	fuaStartBitmask   = 0x80

	interleaved = true
)
var donSN uint16 = 0

func annexbNALUStartCode() []byte { return []byte{0x00, 0x00, 0x00, 0x01} }

func emitNalus(nals []byte, emit func([]byte)) {
	nextInd := func(nalu []byte, start int) (indStart int, indLen int) {
		zeroCount := 0

		for i, b := range nalu[start:] {
			if b == 0 {
				zeroCount++
				continue
			} else if b == 1 {
				if zeroCount >= 2 {
					return start + i - zeroCount, zeroCount + 1
				}
			}
			zeroCount = 0
		}
		return -1, -1
	}

	nextIndStart, nextIndLen := nextInd(nals, 0)
	if nextIndStart == -1 {
		emit(nals)
	} else {
		for nextIndStart != -1 {
			prevStart := nextIndStart + nextIndLen
			nextIndStart, nextIndLen = nextInd(nals, prevStart)
			if nextIndStart != -1 {
				emit(nals[prevStart:nextIndStart])
			} else {
				// Emit until end of stream, no end indicator found
				emit(nals[prevStart:])
			}
		}
	}
}

// convert Nal to STAP-B Payload
func NalToStapBPayload(nalu []byte) []byte{

	naluType := nalu[0] & naluTypeBitmask
	naluRefIdc := nalu[0] & naluRefIdcBitmask

	out := make([]byte, stapbHeaderSize + donSize + stapbNALULengthSize + len(nalu))

	// +---------------+
	// |0|1|2|3|4|5|6|7|
	// +-+-+-+-+-+-+-+-+
	// |F|NRI|  Type   |
	// +---------------+
	out[0] = stapbNALUType
	out[0] |= naluRefIdc

	binary.BigEndian.PutUint16(out[stapbHeaderSize:], donSN)
	binary.BigEndian.PutUint16(out[stapbHeaderSize+donSize:], uint16(len(nalu)))

	copy(out[stapbHeaderSize+donSize+stapaNALULengthSize:], nalu)

	// increase donSN only for new frames (nonIdr).
	// not for SPS, PPS
	if naluType == 1 {
		donSN++
	}

	return out
}

// convert Nal to FU-A Payloads
func NalToFuAPayload(mtu int, nalu []byte) [][]byte {

	var payloads [][]byte

	naluType := nalu[0] & naluTypeBitmask
	naluRefIdc := nalu[0] & naluRefIdcBitmask

	// FU-A
	maxFragmentSize := mtu - fuaHeaderSize

	// The FU payload consists of fragments of the payload of the fragmented
	// NAL unit so that if the fragmentation unit payloads of consecutive
	// FUs are sequentially concatenated, the payload of the fragmented NAL
	// unit can be reconstructed.  The NAL unit type octet of the fragmented
	// NAL unit is not included as such in the fragmentation unit payload,
	// 	but rather the information of the NAL unit type octet of the
	// fragmented NAL unit is conveyed in the F and NRI fields of the FU
	// indicator octet of the fragmentation unit and in the type field of
	// the FU header.  An FU payload MAY have any number of octets and MAY
	// be empty.

	naluData := nalu
	// According to the RFC, the first octet is skipped due to redundant information
	naluDataIndex := 1
	naluDataLength := len(nalu) - naluDataIndex
	naluDataRemaining := naluDataLength

	if min(maxFragmentSize, naluDataRemaining) <= 0 {
		return payloads
	}

	for naluDataRemaining > 0 {
		currentFragmentSize := min(maxFragmentSize, naluDataRemaining)
		out := make([]byte, fuaHeaderSize+currentFragmentSize)

		// +---------------+
		// |0|1|2|3|4|5|6|7|
		// +-+-+-+-+-+-+-+-+
		// |F|NRI|  Type   |
		// +---------------+
		out[0] = fuaNALUType
		out[0] |= naluRefIdc

		// +---------------+
		// |0|1|2|3|4|5|6|7|
		// +-+-+-+-+-+-+-+-+
		// |S|E|R|  Type   |
		// +---------------+

		out[1] = naluType
		if naluDataRemaining == naluDataLength {
			// Set start bit
			out[1] |= 1 << 7
		} else if naluDataRemaining-currentFragmentSize == 0 {
			// Set end bit
			out[1] |= 1 << 6
		}

		copy(out[fuaHeaderSize:], naluData[naluDataIndex:naluDataIndex+currentFragmentSize])
		payloads = append(payloads, out)

		naluDataRemaining -= currentFragmentSize
		naluDataIndex += currentFragmentSize
	}
	return payloads
}

// convert Nal to FU-B Payloads
func NalToFuBPayload(mtu int, nalu []byte) [][]byte{

	var payloads [][]byte

	naluType := nalu[0] & naluTypeBitmask
	naluRefIdc := nalu[0] & naluRefIdcBitmask

	// FU-B
	maxFragmentSize := mtu - fubHeaderSize

	// The FU payload consists of fragments of the payload of the fragmented
	// NAL unit so that if the fragmentation unit payloads of consecutive
	// FUs are sequentially concatenated, the payload of the fragmented NAL
	// unit can be reconstructed.  The NAL unit type octet of the fragmented
	// NAL unit is not included as such in the fragmentation unit payload,
	//  but rather the information of the NAL unit type octet of the
	// fragmented NAL unit is conveyed in the F and NRI fields of the FU
	// indicator octet of the fragmentation unit and in the type field of
	// the FU header.  An FU payload MAY have any number of octets and MAY
	// be empty.

	naluData := nalu
	// According to the RFC, the first octet is skipped due to redundant information
	naluDataIndex := 1
	naluDataLength := len(nalu) - naluDataIndex
	naluDataRemaining := naluDataLength

	if min(maxFragmentSize, naluDataRemaining) <= 0 {
		return payloads
	}
	var currentFragmentSize int

	for naluDataRemaining > 0 {
		var out []byte
		// first fragment, mark as FU-B
		if naluDataRemaining == naluDataLength {

			maxFragmentSize = mtu - fubHeaderSize - donSize
			currentFragmentSize = min(maxFragmentSize, naluDataRemaining)
			out = make([]byte, fubHeaderSize + donSize +  currentFragmentSize)

			// +---------------+
			// |0|1|2|3|4|5|6|7|
			// +-+-+-+-+-+-+-+-+
			// |F|NRI|  Type   |
			// +---------------+

			out[0] = fubNALUType
			out[0] |= naluRefIdc

		} else {
			maxFragmentSize = mtu - fubHeaderSize
			currentFragmentSize = min(maxFragmentSize, naluDataRemaining)

			out = make([]byte, fuaHeaderSize + currentFragmentSize)

			// +---------------+
			// |0|1|2|3|4|5|6|7|
			// +-+-+-+-+-+-+-+-+
			// |F|NRI|  Type   |
			// +---------------+

			out[0] = fuaNALUType
			out[0] |= naluRefIdc
		}

		// +---------------+
		// |0|1|2|3|4|5|6|7|
		// +-+-+-+-+-+-+-+-+
		// |S|E|R|  Type   |
		// +---------------+

		out[1] = naluType
		if naluDataRemaining == naluDataLength {
			// Set start bit
			out[1] |= 1 << 7

			// copy the don into the array
			binary.BigEndian.PutUint16(out[fuaHeaderSize:], donSN)
			donSN++
			// copy the nal into the array
			copy(out[fuaHeaderSize + donSize:], naluData[naluDataIndex:naluDataIndex+currentFragmentSize])

		} else if naluDataRemaining-currentFragmentSize == 0 {
			// Set end bit
			out[1] |= 1 << 6
			copy(out[fuaHeaderSize:], naluData[naluDataIndex:naluDataIndex+currentFragmentSize])
		} else {
			copy(out[fuaHeaderSize:], naluData[naluDataIndex:naluDataIndex+currentFragmentSize])
		}

		payloads = append(payloads, out)

		naluDataRemaining -= currentFragmentSize
		naluDataIndex += currentFragmentSize
	}

	return payloads
}

// Payload fragments a H264 packet across one or more byte arrays
func (p *H264Payloader) Payload(mtu int, payload []byte) [][]byte {
	var payloads [][]byte
	if payload == nil {
		return payloads
	}

	emitNalus(payload, func(nalu []byte) {
		naluType := nalu[0] & naluTypeBitmask
		//naluRefIdc := nalu[0] & naluRefIdcBitmask

		if naluType == 9 || naluType == 12  {
			return
		}

		// Single NALU
		if !interleaved {

			if len(nalu) <= mtu {
				out := make([]byte, len(nalu))
				copy(out, nalu)
				payloads = append(payloads, out)
				return
			}

			payloads = append(payloads, NalToFuAPayload(mtu, nalu)...)

		} else {

			if len(nalu) + stapbHeaderSize + donSize + stapbNALULengthSize <= mtu {
				payloads = append(payloads, NalToStapBPayload(nalu))
				return
			}

			payloads = append(payloads, NalToFuBPayload(mtu, nalu)...)
		}

	})

	return payloads
}

// H264Packet represents the H264 header that is stored in the payload of an RTP Packet
type H264Packet struct {
}

// Unmarshal parses the passed byte slice and stores the result in the H264Packet this method is called upon
func (p *H264Packet) Unmarshal(payload []byte) ([]byte, error) {
	if payload == nil {
		return nil, errNilPacket
	} else if len(payload) <= 2 {
		return nil, fmt.Errorf("%w: %d <= 2", errShortPacket, len(payload))
	}

	// NALU Types
	// https://tools.ietf.org/html/rfc6184#section-5.4
	naluType := payload[0] & naluTypeBitmask
	switch {
	case naluType > 0 && naluType < 24:
		return append(annexbNALUStartCode(), payload...), nil

	case naluType == stapaNALUType:
		currOffset := int(stapaHeaderSize)
		result := []byte{}
		for currOffset < len(payload) {
			naluSize := int(binary.BigEndian.Uint16(payload[currOffset:]))
			currOffset += stapaNALULengthSize

			if len(payload) < currOffset+naluSize {
				return nil, fmt.Errorf("%w STAP-A declared size(%d) is larger than buffer(%d)", errShortPacket, naluSize, len(payload)-currOffset)
			}

			result = append(result, annexbNALUStartCode()...)
			result = append(result, payload[currOffset:currOffset+naluSize]...)
			currOffset += naluSize
		}
		return result, nil

	case naluType == fuaNALUType:
		if len(payload) < fuaHeaderSize {
			return nil, errShortPacket
		}

		if payload[1]&fuaStartBitmask != 0 {
			naluRefIdc := payload[0] & naluRefIdcBitmask
			fragmentedNaluType := payload[1] & naluTypeBitmask

			// Take a copy of payload since we are mutating it.
			payloadCopy := append([]byte{}, payload...)
			payloadCopy[fuaHeaderSize-1] = naluRefIdc | fragmentedNaluType
			return append(annexbNALUStartCode(), payloadCopy[fuaHeaderSize-1:]...), nil
		}

		return payload[fuaHeaderSize:], nil
	}

	return nil, fmt.Errorf("%w: %d", errUnhandledNALUType, naluType)
}
