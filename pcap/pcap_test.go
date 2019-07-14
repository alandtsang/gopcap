package pcap

import (
	"fmt"
	"testing"
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
	fmt.Println("data=", data)
}
