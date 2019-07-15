package pcap

import (
	"fmt"
	"testing"

	"github.com/alandtsang/gopcap/layers"
)

func TestPcapFileRead(t *testing.T) {
	filename := "test_tcp.pcap"
	fmt.Println(filename)

	var handle *Pcap
	var err error

	handle, err = OpenOffline(filename)
	if err != nil {
		t.Fatal(err)
	}

	data, err := handle.ReadPacketData()
	//fmt.Println("data=", data)

	//pkt := NewPacket(data)
	//fmt.Println("pkt=", pkt)
	layers.DecodeEthernet(data)
	layers.DecodeIPv4(data[14:])
	layers.DecodeTCP(data[34:])
}
