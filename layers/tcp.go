package layers

// TCP is the layer for TCP headers.
type TCP struct {
	SrcPort, DstPort                           uint16
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	sPort, dPort                               []byte
	Options                                    []TCPOption
	Padding                                    []byte
	opts                                       [4]TCPOption
	//tcpipchecksum
}

type TCPOption struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}
