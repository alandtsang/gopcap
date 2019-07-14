package pcap

import "github.com/alandtsang/gopcap/layers"

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
