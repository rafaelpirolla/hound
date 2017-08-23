// /////////////////////////////////////////////////////////////////////////////

package main

// /////////////////////////////////////////////////////////////////////////////

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// /////////////////////////////////////////////////////////////////////////////
// CONSTANTS
// /////////////////////////////////////////////////////////////////////////////

const (
	snapshotLength = 1024
	usePromiscuous = false
	timeout        = -1 * time.Second
	tmpFilePrefix  = "hound-"
)

// /////////////////////////////////////////////////////////////////////////////
// TYPES
// /////////////////////////////////////////////////////////////////////////////

type PacketCapturer interface {
	GetDevice() (*pcap.Handle, error)
	GetFile(string) (*gopacket.PacketSource, error)
	GetFilter() string
	StartCapture() (string, error)
}

type PacketCapture struct {
	Config *Config
}

// /////////////////////////////////////////////////////////////////////////////
// METHODS
// /////////////////////////////////////////////////////////////////////////////

func NewPacketCapture(config *Config) (*PacketCapture, error) {
	pc := new(PacketCapture)
	pc.Config = config
	return pc, nil
}

// /////////////////////////////////////////////////////////////////////////////

func (pc *PacketCapture) GetDevice() (*pcap.Handle, error) {
	device := (*pc).Config.Device

	if device == "" {
		devices, err := pcap.FindAllDevs()

		if err != nil {
			return nil, errors.New("no devices available for capturing")
		}

		for _, d := range devices {
			if len(d.Addresses) >= 1 {
				device = d.Name
				break
			}
		}

		if device == "" {
			return nil, errors.New("no devices have IPv4 addresses assigned to them")
		}
	}

	handle, err := pcap.OpenLive(device, snapshotLength, usePromiscuous, timeout)

	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter((*pc).GetFilter())

	if err != nil {
		return nil, err
	}

	return handle, nil
}

// /////////////////////////////////////////////////////////////////////////////

func (pc *PacketCapture) GetFile(fn string) (*gopacket.PacketSource, error) {
	handle, err := pcap.OpenOffline(fn)

	if err != nil {
		return nil, err
	}

	filter := pc.GetFilter()
	err = handle.SetBPFFilter(filter)

	if err != nil {
		return nil, err
	}

	return gopacket.NewPacketSource(handle, handle.LinkType()), nil
}

// /////////////////////////////////////////////////////////////////////////////

func (pc *PacketCapture) GetFilter() string {
	hosts := ""

	for i, ip := range (*pc).Config.CustomerIPs {
		hosts = hosts + "host " + ip

		if i < len((*pc).Config.CustomerIPs)-1 {
			hosts = hosts + " or "
		}
	}

	ports := ""

	for i, port := range (*pc).Config.Ports {
		ports = ports + "port " + strconv.Itoa(port)

		if i < len((*pc).Config.Ports)-1 {
			ports = ports + " or "
		}
	}

	filter := fmt.Sprintf("(ip) and (%s) and tcp and (%s)", hosts, ports)

	return filter
}

// /////////////////////////////////////////////////////////////////////////////

func (pc *PacketCapture) StartCapture() (string, error) {
	device, err := (*pc).GetDevice()

	if err != nil {
		return "", err
	}

	pktSrc := gopacket.NewPacketSource(device, device.LinkType())
	chPacket := pktSrc.Packets()
	chTimeout := make(chan bool, 1)
	duration := time.Duration((*pc).Config.Duration) * time.Second

	tmpFile, err := ioutil.TempFile("", tmpFilePrefix)

	if err != nil {
		return "", err
	}

	defer tmpFile.Close()

	writer := pcapgo.NewWriter(tmpFile)
	writer.WriteFileHeader(snapshotLength, layers.LinkTypeEthernet)

	go func() {
		time.Sleep(duration)
		chTimeout <- true
	}()

	for {
		select {
		case packet := <-chPacket:
			writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		case <-chTimeout:
			return tmpFile.Name(), nil
		}
	}
}

// /////////////////////////////////////////////////////////////////////////////
