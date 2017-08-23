// /////////////////////////////////////////////////////////////////////////////

package main

// /////////////////////////////////////////////////////////////////////////////

import (
	"errors"
	"net"
	"time"
)

// /////////////////////////////////////////////////////////////////////////////
// TYPES
// /////////////////////////////////////////////////////////////////////////////

type Connection interface {
	AddDstSample(uint32) (*TCPSample, error)
	AddSrcSample(uint32) (*TCPSample, error)
	Belongs(*TCPPacket) bool
	FindDstSample(seq uint32) *TCPSample
	FindSrcSample(seq uint32) *TCPSample
	IsIncoming(p *TCPPacket) bool
	IsOutgoing(p *TCPPacket) bool
	IsSamplePresent(uint32, *SampleMap) bool
}

type TCPConnection struct {
	SrcIP           net.IP
	SrcPort         uint16
	DstIP           net.IP
	DstPort         uint16
	SamplesSrcToDst SampleMap
	SamplesDstToSrc SampleMap
	IsEstablished   bool
	NextSrcSeq      uint32
	NextDstSeq      uint32
	IRtt            float64
	Start           time.Time
}

// /////////////////////////////////////////////////////////////////////////////

func NewTCPConnection(p *TCPPacket) (*TCPConnection, error) {
	cn := new(TCPConnection)
	seq := (*p).TCP.Seq + 1

	(*cn).SrcIP = (*p).IP.SrcIP
	(*cn).DstIP = (*p).IP.DstIP
	(*cn).SrcPort = uint16((*p).TCP.SrcPort)
	(*cn).DstPort = uint16((*p).TCP.DstPort)
	(*cn).SamplesSrcToDst = make(SampleMap)
	(*cn).SamplesDstToSrc = make(SampleMap)
	(*cn).IsEstablished = false
	(*cn).NextSrcSeq = seq
	(*cn).NextDstSeq = 0
	(*cn).IRtt = 0
	(*cn).Start = (*p).MetaData.Timestamp
	(*cn).AddSrcSample(seq, p)

	return cn, nil
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) AddDstSample(seq uint32, p *TCPPacket) (*TCPSample, error) {
	if (*cn).IsSamplePresent(seq, &((*cn).SamplesDstToSrc)) {
		sp, err := NewTCPSample(p)

		if err != nil {
			return nil, err
		} else {
			(*cn).SamplesDstToSrc[seq] = sp
			return sp, nil
		}
	}

	return nil, errors.New("This sequence number is already present")
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) AddSrcSample(seq uint32, p *TCPPacket) (*TCPSample, error) {
	if (*cn).IsSamplePresent(seq, &((*cn).SamplesSrcToDst)) {
		sp, err := NewTCPSample(p)

		if err != nil {
			return nil, err
		} else {
			if (*cn).IsSamplePresent(seq, &((*cn).SamplesSrcToDst)) {
				(*cn).SamplesSrcToDst[seq] = sp
				return sp, nil
			} else {
				return (*cn).SamplesSrcToDst[seq], nil
			}
		}
	}

	return nil, errors.New("This sequence number is already present")
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) Belongs(p *TCPPacket) bool {
	if uint16((*p).TCP.SrcPort) == (*cn).SrcPort || uint16((*p).TCP.SrcPort) == (*cn).DstPort {
		return true
	}

	return false
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) FindDstSample(seq uint32) *TCPSample {
	if cn.IsSamplePresent(seq, &(cn.SamplesDstToSrc)) {
		return cn.SamplesDstToSrc[seq]
	}

	return nil
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) FindSrcSample(seq uint32) *TCPSample {
	if cn.IsSamplePresent(seq, &(cn.SamplesSrcToDst)) {
		return cn.SamplesSrcToDst[seq]
	}

	return nil
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) IsIncoming(p *TCPPacket) bool {
	if p.IP.SrcIP.Equal(cn.DstIP) && p.IP.DstIP.Equal(cn.SrcIP) {
		return true
	}

	return false
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) IsOutgoing(p *TCPPacket) bool {
	if p.IP.SrcIP.Equal(cn.SrcIP) && p.IP.DstIP.Equal(cn.DstIP) {
		return true
	}

	return false
}

// /////////////////////////////////////////////////////////////////////////////

func (cn *TCPConnection) IsSamplePresent(seq uint32, sm *SampleMap) bool {
	_, ok := (*sm)[seq]
	return ok
}

// /////////////////////////////////////////////////////////////////////////////
