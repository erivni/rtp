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

	/* build payload length header and preppend it to payload */
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
