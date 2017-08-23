// /////////////////////////////////////////////////////////////////////////////

package main

// /////////////////////////////////////////////////////////////////////////////

import (
	"container/list"
)

// /////////////////////////////////////////////////////////////////////////////
// CONSTANTS
// /////////////////////////////////////////////////////////////////////////////

const (
	directionSrcToDst = 0x1
	directionDstToSrc = 0x2
)

// /////////////////////////////////////////////////////////////////////////////
// TYPES
// /////////////////////////////////////////////////////////////////////////////

type Analysis interface {
	Append(*TCPPacket) (*TCPConnection, error)
	Find(*TCPPacket) *TCPConnection
	Run(string) (*list.List, error)
}

type TCPAnalysis struct {
	Config      *Config
	Connections *list.List
}

// /////////////////////////////////////////////////////////////////////////////
// METHODS
// /////////////////////////////////////////////////////////////////////////////

func NewTCPAnalysis(config *Config) (*TCPAnalysis, error) {
	an := new(TCPAnalysis)
	an.Config = config
	an.Connections = list.New()
	return an, nil
}

// /////////////////////////////////////////////////////////////////////////////

func (an *TCPAnalysis) Append(p *TCPPacket) (*TCPConnection, error) {
	cn, err := NewTCPConnection(p)

	if err != nil {
		return nil, err
	}

	an.Connections.PushBack(cn)
	return cn, nil
}

// /////////////////////////////////////////////////////////////////////////////

func (an *TCPAnalysis) Find(p *TCPPacket) *TCPConnection {
	e := an.Connections.Front()

	for ; e != nil; e = e.Next() {
		cn := e.Value.(*TCPConnection)

		if (*cn).Belongs(p) {
			return cn
		}
	}

	return nil
}

// /////////////////////////////////////////////////////////////////////////////

func (an *TCPAnalysis) Run(fn string) (*list.List, error) {
	pc, err := NewPacketCapture(an.Config)

	if err != nil {
		return an.Connections, err
	}

	ps, err := pc.GetFile(fn)

	if err != nil {
		return an.Connections, err
	}

	for packet := range ps.Packets() {
		p, err := NewTCPPacket(&packet)

		if err != nil {
			return an.Connections, err
		}

		if (*p).IsOpeningConnection() {
			_, err := (*an).Append(p)

			if err != nil {
				return (*an).Connections, err
			}
		} else if (*p).IsEstablishingConnection() {
			cn := (*an).Find(p)

			if cn != nil {
				sp := cn.FindSrcSample(p.TCP.Ack)

				if sp != nil {
					(*sp).CalculateRTT(p)
				}

				(*cn).AddDstSample((*p).GetExtepctedAck(), p)
			}
		} else if (*p).IsAcking() {
			cn := (*an).Find(p)

			if (*cn).IsOutgoing(p) {
				sp := (*cn).FindDstSample((*p).TCP.Ack)

				if sp != nil {
					(*sp).CalculateRTT(p)
				}

				if (*cn).IsEstablished {
					(*cn).AddSrcSample((*p).GetExtepctedAck(), p)
				} else {
					(*cn).IRtt = (*p).MetaData.Timestamp.Sub((*cn).Start).Seconds()
					(*cn).IsEstablished = true
				}
			} else {
				sp := (*cn).FindSrcSample((*p).TCP.Ack)

				if sp != nil {
					(*sp).CalculateRTT(p)
				}

				(*cn).AddDstSample((*p).GetExtepctedAck(), p)
			}
		}
	}

	return an.Connections, nil
}

// /////////////////////////////////////////////////////////////////////////////
