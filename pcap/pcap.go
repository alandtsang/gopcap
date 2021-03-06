package pcap

import (
	"fmt"
	"strconv"
	"time"
	"unsafe"
)

type Pcap struct {
	cptr   pcapPtr
	device string
	pkthdr *pcapPktHdr
	bufptr *uint8
}

type Stats struct {
	PacketsReceived  int
	PacketsDropped   int
	PacketsIfDropped int
}

func timeoutMillis(timeout time.Duration) int {
	// Flip sign if necessary.  See package docs on timeout for reasoning behind this.
	if timeout < 0 {
		timeout *= -1
	}
	// Round up
	if timeout != 0 && timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	return int(timeout / time.Millisecond)
}

func OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (handle *Pcap, _ error) {
	var pro int
	if promisc {
		pro = 1
	}

	p, err := pcapOpenLive(device, int(snaplen), pro, timeoutMillis(timeout))
	if err != nil {
		return nil, err
	}
	//p.timeout = timeout
	p.device = device
	/*
		ifc, err := net.InterfaceByName(device)
		if err != nil {
			// The device wasn't found in the OS, but could be "any"
			// Set index to 0
			p.deviceIndex = 0
		} else {
			p.deviceIndex = ifc.Index
		}

		p.nanoSecsFactor = 1000

		// Only set the PCAP handle into non-blocking mode if we have a timeout
		// greater than zero. If the user wants to block forever, we'll let libpcap
		// handle that.
		if p.timeout > 0 {
			if err := p.setNonBlocking(); err != nil {
				p.pcapClose()
				return nil, err
			}
		}
	*/
	return p, nil
}

func OpenOffline(file string) (handle *Pcap, err error) {
	handle, err = openOffline(file)
	if err != nil {
		return
	}
	return
}

// NextError is the return code from a call to Next.
type NextError int32

// NextError implements the error interface.
func (n NextError) Error() string {
	switch n {
	case NextErrorOk:
		return "OK"
	case NextErrorTimeoutExpired:
		return "Timeout Expired"
	case NextErrorReadError:
		return "Read Error"
	case NextErrorNoMorePackets:
		return "No More Packets In File"
	case NextErrorNotActivated:
		return "Not Activated"
	}
	return strconv.Itoa(int(n))
}

// NextError values.
const (
	NextErrorOk             NextError = 1
	NextErrorTimeoutExpired NextError = 0
	NextErrorReadError      NextError = -1
	// NextErrorNoMorePackets is returned when reading from a file (OpenOffline) and
	// EOF is reached.  When this happens, Next() returns io.EOF instead of this.
	NextErrorNoMorePackets NextError = -2
	NextErrorNotActivated  NextError = -3
)

func (p *Pcap) ReadPacketData() (data []byte, err error) {
	err = p.getNextBufPtr()
	if err == nil {
		//data = make([]byte, ci.CaptureLength)
		data = make([]byte, 1024)
		copy(data, (*(*[1 << 30]byte)(unsafe.Pointer(p.bufptr)))[:])
	}

	return
}

func (p *Pcap) getNextBufPtr() error {
	result := p.pcapNextPacketEx()
	fmt.Println("result=", result)

	switch result {
	case NextErrorOk:
		sec := p.pkthdr.getSec()
		caplen := p.pkthdr.getCaplen()
		length := p.pkthdr.getLen()

		fmt.Printf("sec:%v, caplen=%d, len=%d\n", sec, caplen, length)
	}
	return nil
}
