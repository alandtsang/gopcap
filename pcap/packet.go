package pcap

import (
	"fmt"

	"github.com/alandtsang/gopcap"
	"github.com/alandtsang/gopcap/layers"
)

type Packet interface {
	Data() []byte
}

type packet struct {
	// data contains the entire packet data for a packet
	data []byte

	// Pointers to the various important layers
	link        layers.LinkLayer
	network     layers.NetworkLayer
	transport   layers.TransportLayer
	application layers.ApplicationLayer
}

func (p *packet) Data() []byte {
	return p.data
}

func (p *packet) initDecode(dec gopcap.Decoder) {
	err := dec.Decode(p.data)
	if err != nil {
		fmt.Println(err)
	}
}

func NewPacket(data []byte) Packet {
	p := &packet{
		data: data,
	}
	return p
}
