package codecs

// AacPayloader payloads MP4A-LATM/AAC audio packets
type AacPayloader struct{}

// Payload fragments an AAC MP4-LATM packet across one or more byte arrays
func (p *AacPayloader) Payload(mtu uint16, payload []byte) [][]byte {
	maxFragmentSize := int(mtu)
	if payload == nil {
		return [][]byte{}
	}

	payloads := [][]byte{}
	nextFragmentIdx := 0
	payloadLength := len(payload)

	/* build payload length header and preppend it to payload
	   Payload length byte size is variable, depending on the size of the payload.
	   e.g. if payload size is 100 bytes, we'll prepend one byte to the payload with 100.
	   If the payload size is greater than 255, we'll need multiple bytes to represent the size.
	   e.g. if payload size is 800 bytes, we'll prepend the following bytes:
	   255,255,255,35. (De-packetizer should sum all the first payload bytes until reaching a byte which is less than 255)
	*/

	headerLengthHeader := []byte{}
	headerLength := 0
	count := payloadLength
	for count >= 0xff {
		headerLength++
		count -= 0xff
		headerLengthHeader = append(headerLengthHeader, 0xff)
	}
	headerLength++
	headerLengthHeader = append(headerLengthHeader, byte(count))
	payload = append(headerLengthHeader, payload...)
	bytesLeft := len(payload)

	// Split payload by MTU size
	for bytesLeft > 0 {
		var fragment []byte

		if bytesLeft < maxFragmentSize {
			fragment = make([]byte, bytesLeft)
		} else {
			fragment = make([]byte, maxFragmentSize)
		}
		fragmentLength := len(fragment)
		copy(fragment, payload[nextFragmentIdx:nextFragmentIdx+fragmentLength])
		payloads = append(payloads, fragment)
		nextFragmentIdx += maxFragmentSize
		bytesLeft -= fragmentLength
	}
	return payloads
}
