package pcap

type Packet interface {
	Data() []byte
}

type packet struct {
	// data contains the entire packet data for a packet
	data []byte

	// Pointers to the various important layers
	link        LinkLayer
	network     NetworkLayer
	transport   TransportLayer
	application ApplicationLayer
}
