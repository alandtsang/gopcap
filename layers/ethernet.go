package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type Ethernet struct {
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   uint16
	// Length is only set if a length field exists within this header.  Ethernet
	// headers follow two different standards, one that uses an EthernetType, the
	// other which defines a length the follows with a LLC header (802.3).  If the
	// former is the case, we set EthernetType and Length stays 0.  In the latter
	// case, we set Length and EthernetType = EthernetTypeLLC.
	Length uint16
}

func (eth *Ethernet) DecodeFromBytes(data []byte) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}
	eth.DstMAC = net.HardwareAddr(data[0:6])
	eth.SrcMAC = net.HardwareAddr(data[6:12])
	eth.EthernetType = EthernetType(binary.BigEndian.Uint16(data[12:14]))
	//eth.BaseLayer = BaseLayer{data[:14], data[14:]}
	eth.Length = 0
	fmt.Printf("%v\n", eth)
	/*
		if eth.EthernetType < 0x0600 {
			eth.Length = uint16(eth.EthernetType)
			eth.EthernetType = EthernetTypeLLC
			if cmp := len(eth.Payload) - int(eth.Length); cmp < 0 {
			} else if cmp > 0 {
				// Strip off bytes at the end, since we have too many bytes
				eth.Payload = eth.Payload[:len(eth.Payload)-cmp]
			}
			//	fmt.Println(eth)
		}
	*/
	return nil
}
