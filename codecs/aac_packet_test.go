package codecs

import (
	"testing"
)

func TestAacPayloader_Payload(t *testing.T) {
	pck := AacPayloader{}
	payload := []byte{0x90, 0x90, 0x90}

	// Positive MTU, nil payload
	res := pck.Payload(10, nil)
	if len(res) != 0 {
		t.Fatal("Generated payload packets count packet count should be empty")
	}

	// Large MTU, small payload. Payload (3 bytes) + size byte (1 byte) are less than MTU(10), should get single payload of 4 bytes
	res = pck.Payload(10, payload)
	if len(res) != 1 {
		t.Fatal("Generated payload packets count should be 1")
	}
	if len(res[0]) != 4 {
		t.Fatal("Generated payload[0] length should be 4")
	}
	if res[0][0] != 0x03 {
		t.Fatal("res[0][0] should be 0x03 (Payload size byte)")
	}

	// Small MTU, large payload fragmentation. Payload(9 bytes) + size byte (1 byte) are more than MTU(6), should get two payloads, 6 bytes and 4 bytes
	payload = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	res = pck.Payload(6, payload)
	if len(res) != 2 {
		t.Fatal("Generated payload packets count should be 2 (fragmentation expected)")
	}
	if len(res[0]) != 6 {
		t.Fatal("Generated payload[0] length should be 6")
	}
	if res[0][1] != 0x01 {
		t.Fatal("Generated payload[0][1] length should be 0x01 (First payload data after size byte)")
	}

	if len(res[1]) != 4 {
		t.Fatal("Generated payload[1] length should be 4")
	}
	if res[1][0] != 0x06 {
		t.Fatal("Generated payload[0][0] length should be 0x06 (First payload data)")
	}
}
