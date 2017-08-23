// /////////////////////////////////////////////////////////////////////////////

package main

// /////////////////////////////////////////////////////////////////////////////

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// /////////////////////////////////////////////////////////////////////////////
// TYPES
// /////////////////////////////////////////////////////////////////////////////

type Packet interface {
	GetTimestamps() (uint32, uint32)
	GetExtepctedAck() uint32
	IsAcking() bool
	IsEstablishingConnection() bool
	IsOpeningConnection() bool
}

type TCPPacket struct {
	MetaData gopacket.PacketMetadata
	IP       layers.IPv4
	TCP      layers.TCP
}

// /////////////////////////////////////////////////////////////////////////////
// METHODS
// /////////////////////////////////////////////////////////////////////////////

func NewTCPPacket(packet *gopacket.Packet) (*TCPPacket, error) {
	p := new(TCPPacket)
	(*p).MetaData = *(*packet).Metadata()
	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)

	if ipLayer != nil {
		p.IP = *(ipLayer.(*layers.IPv4))
	} else {
		return nil, errors.New("Could not get IP layer from packet")
	}

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)

	if tcpLayer != nil {
		p.TCP = *(tcpLayer.(*layers.TCP))
	} else {
		return nil, errors.New("Could not get TCP layer from packet")
	}

	return p, nil
}

// /////////////////////////////////////////////////////////////////////////////

func (p *TCPPacket) GetTimestamps() (uint32, uint32) {
	for _, option := range p.TCP.Options {
		if option.OptionType == layers.TCPOptionKindTimestamps {
			tsVal := binary.BigEndian.Uint32(option.OptionData[:4])
			tsEcr := binary.BigEndian.Uint32(option.OptionData[4:])

			return tsVal, tsEcr
		}
	}

	return 0, 0
}

// /////////////////////////////////////////////////////////////////////////////

func (p *TCPPacket) GetExtepctedAck() uint32 {
	if (*p).TCP.SYN {
		return (*p).TCP.Seq + 1
	}

	return (*p).TCP.Seq + uint32(len((*p).TCP.Payload))
}

// /////////////////////////////////////////////////////////////////////////////

func (p *TCPPacket) IsOpeningConnection() bool {
	return p.TCP.SYN && !p.TCP.ACK
}

// /////////////////////////////////////////////////////////////////////////////

func (p *TCPPacket) IsEstablishingConnection() bool {
	return p.TCP.SYN && p.TCP.ACK
}

// /////////////////////////////////////////////////////////////////////////////

func (p *TCPPacket) IsAcking() bool {
	return p.TCP.ACK && !p.TCP.SYN && !p.TCP.RST && !p.TCP.FIN
}

// /////////////////////////////////////////////////////////////////////////////
