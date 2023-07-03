package rtp

import (
	"github.com/pion/rtp/codecs"
	"time"
)

type interleavedPacketizer struct {
	MTU                  uint16
	PayloadType          uint8
	SSRC                 uint32
	Payloader            Payloader
	Sequencer            Sequencer
	Timestamp            uint32
	InterleavedTimestamp uint32 // use for packetizing future samples
	ClockRate            uint32
	extensionNumbers     struct { // put extension numbers in here. If they're 0, the extension is disabled (0 is not a legal extension number)
		AbsSendTime int // http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
	}
	timegen         func() time.Time
}

// NewPacketizer returns a new instance of a Packetizer for a specific payloader
func NewInterleavedPacketizer(mtu uint16, pt uint8, ssrc uint32, payloader Payloader, sequencer Sequencer, clockRate uint32) Packetizer {
	return &interleavedPacketizer{
		MTU:             mtu,
		PayloadType:     pt,
		SSRC:            ssrc,
		Payloader:       payloader,
		Sequencer:       sequencer,
		Timestamp:       globalMathRandomGenerator.Uint32(),
		ClockRate:       clockRate,
		timegen:         time.Now,
	}
}

func (p *interleavedPacketizer) EnableAbsSendTime(value int) {
	p.extensionNumbers.AbsSendTime = value
}
func (p *interleavedPacketizer) SkipSamples(skippedSamples uint32) {
	p.Timestamp += skippedSamples
}

func (p *interleavedPacketizer) SkipInterleavedSamples(skippedSamples uint32) {
	p.InterleavedTimestamp += skippedSamples
}

func (p *interleavedPacketizer) PacketizeAndDetectData(payload []byte, samples uint32) ([]*Packet, int) {
	// Guard against an empty payload
	if len(payload) == 0 {
		return nil, -1
	}

	var payloads [][]byte
	var payloadDataIdx int

	switch p.Payloader.(type) {
	case *codecs.H264Payloader:
		payloads, payloadDataIdx = p.Payloader.(*codecs.H264Payloader).PayloadAndDetectData(p.MTU-12, payload)
	default:
		payloads = p.Payloader.Payload(p.MTU-12, payload)
	}

	packets := make([]*Packet, len(payloads))

	for i, pp := range payloads {
		packets[i] = &Packet{
			Header: Header{
				Version:        2,
				Padding:        false,
				Extension:      false,
				Marker:         i == len(payloads)-1,
				PayloadType:    p.PayloadType,
				SequenceNumber: p.Sequencer.NextSequenceNumber(),
				Timestamp:      p.Timestamp, // Figure out how to do timestamps
				SSRC:           p.SSRC,
			},
			Payload: pp,
		}
	}
	p.Timestamp += samples

	if len(packets) != 0 && p.extensionNumbers.AbsSendTime != 0 {
		sendTime := NewAbsSendTimeExtension(p.timegen())
		// apply http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
		b, err := sendTime.Marshal()
		if err != nil {
			return nil, -1 // never happens
		}
		err = packets[len(packets)-1].SetExtension(uint8(p.extensionNumbers.AbsSendTime), b)
		if err != nil {
			return nil, -1 // never happens
		}
	}

	return packets, payloadDataIdx
}

// Packetize packetizes the payload of an RTP packet and returns one or more RTP packets
func (p *interleavedPacketizer) Packetize(payload []byte, samples uint32) []*Packet {
	// Guard against an empty payload
	if len(payload) == 0 {
		return nil
	}

	payloads := p.Payloader.Payload(p.MTU-12, payload)
	packets := make([]*Packet, len(payloads))

	for i, pp := range payloads {
		packets[i] = &Packet{
			Header: Header{
				Version:        2,
				Padding:        false,
				Extension:      false,
				Marker:         i == len(payloads)-1,
				PayloadType:    p.PayloadType,
				SequenceNumber: p.Sequencer.NextSequenceNumber(),
				Timestamp:      p.Timestamp, // Figure out how to do timestamps
				SSRC:           p.SSRC,
			},
			Payload: pp,
		}
	}
	p.Timestamp += samples

	if len(packets) != 0 && p.extensionNumbers.AbsSendTime != 0 {
		sendTime := NewAbsSendTimeExtension(p.timegen())
		// apply http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
		b, err := sendTime.Marshal()
		if err != nil {
			return nil // never happens
		}
		err = packets[len(packets)-1].SetExtension(uint8(p.extensionNumbers.AbsSendTime), b)
		if err != nil {
			return nil // never happens
		}
	}

	return packets
}

// PacketizeInterleaved packetizes the payload of an RTP packet and returns one or more RTP packets
func (p *interleavedPacketizer) PacketizeInterleaved(payload []byte, samples uint32) []*Packet {
	// Guard against an empty payload
	if len(payload) == 0 {
		return nil
	}

	payloads := p.Payloader.Payload(p.MTU-12, payload)
	packets := make([]*Packet, len(payloads))

	for i, pp := range payloads {
		packets[i] = &Packet{
			Header: Header{
				Version:        2,
				Padding:        false,
				Extension:      false,
				Marker:         i == len(payloads)-1,
				PayloadType:    p.PayloadType,
				SequenceNumber: p.Sequencer.NextSequenceNumber(),
				Timestamp:      p.InterleavedTimestamp, // Figure out how to do timestamps
				SSRC:           p.SSRC,
			},
			Payload: pp,
		}
	}
	p.InterleavedTimestamp += samples

	if len(packets) != 0 && p.extensionNumbers.AbsSendTime != 0 {
		sendTime := NewAbsSendTimeExtension(p.timegen())
		// apply http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
		b, err := sendTime.Marshal()
		if err != nil {
			return nil // never happens
		}
		err = packets[len(packets)-1].SetExtension(uint8(p.extensionNumbers.AbsSendTime), b)
		if err != nil {
			return nil // never happens
		}
	}

	return packets
}

// PacketizeInterleavedAndDetectData packetizes the payload of an RTP packet and returns one or more RTP packets
func (p *interleavedPacketizer) PacketizeInterleavedAndDetectData(payload []byte, samples uint32) ([]*Packet, int) {
	// Guard against an empty payload
	if len(payload) == 0 {
		return nil, -1
	}
	
	var payloads [][]byte
	var payloadDataIdx int = 0 // data is in first payload unless otherwise detected. including non h264 payloaders

	switch p.Payloader.(type) {
	case *codecs.H264Payloader:
		payloads, payloadDataIdx = p.Payloader.(*codecs.H264Payloader).PayloadAndDetectData(p.MTU-12, payload)
	default:
		payloads = p.Payloader.Payload(p.MTU-12, payload)
	}
	
	packets := make([]*Packet, len(payloads))

	for i, pp := range payloads {
		packets[i] = &Packet{
			Header: Header{
				Version:        2,
				Padding:        false,
				Extension:      false,
				Marker:         i == len(payloads)-1,
				PayloadType:    p.PayloadType,
				SequenceNumber: p.Sequencer.NextSequenceNumber(),
				Timestamp:      p.InterleavedTimestamp, // Figure out how to do timestamps
				SSRC:           p.SSRC,
			},
			Payload: pp,
		}
	}
	p.InterleavedTimestamp += samples

	if len(packets) != 0 && p.extensionNumbers.AbsSendTime != 0 {
		sendTime := NewAbsSendTimeExtension(p.timegen())
		// apply http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
		b, err := sendTime.Marshal()
		if err != nil {
			return nil, -1 // never happens
		}
		err = packets[len(packets)-1].SetExtension(uint8(p.extensionNumbers.AbsSendTime), b)
		if err != nil {
			return nil, -1 // never happens
		}
	}

	return packets, payloadDataIdx
}

func (p *interleavedPacketizer) SetTimestamps(timestamp uint32, interleavedTimestamp uint32) {
	if timestamp > 0 {
		p.Timestamp = timestamp
	}
	if interleavedTimestamp > 0 {
		p.InterleavedTimestamp = interleavedTimestamp
	}
}

func (p *interleavedPacketizer) GetTimestamps() (uint32, uint32) {
	return p.Timestamp, p.InterleavedTimestamp
}

func (p *interleavedPacketizer) GetCurrentSequenceNumber() uint16 {
	return p.Sequencer.CurrentSequenceNumber()
}
