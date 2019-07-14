package layers

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPv4 is the header of an IP packet.
type IPv4 struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      IPv4Flag
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []IPv4Option
	Padding    []byte
}

func (ip *IPv4) DecodeFromBytes(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("Invalid ip4 header. Length %d less than 20", len(data))
	}
	flagsfrags := binary.BigEndian.Uint16(data[6:8])

	ip.Version = uint8(data[0]) >> 4
	ip.IHL = uint8(data[0]) & 0x0F
	ip.TOS = data[1]
	ip.Length = binary.BigEndian.Uint16(data[2:4])
	ip.Id = binary.BigEndian.Uint16(data[4:6])
	ip.Flags = IPv4Flag(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.TTL = data[8]
	ip.Protocol = IPProtocol(data[9])
	ip.Checksum = binary.BigEndian.Uint16(data[10:12])
	ip.SrcIP = data[12:16]
	ip.DstIP = data[16:20]
	ip.Options = ip.Options[:0]
	ip.Padding = nil
	// Set up an initial guess for contents/payload... we'll reset these soon.
	//ip.BaseLayer = BaseLayer{Contents: data}

	// This code is added for the following enviroment:
	// * Windows 10 with TSO option activated. ( tested on Hyper-V, RealTek ethernet driver )
	if ip.Length == 0 {
		// If using TSO(TCP Segmentation Offload), length is zero.
		// The actual packet length is the length of data.
		ip.Length = uint16(len(data))
	}
}
