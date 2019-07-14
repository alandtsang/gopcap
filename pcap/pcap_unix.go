package pcap

/*
#cgo solaris LDFLAGS: -L /opt/local/lib -lpcap
#cgo linux LDFLAGS: -lpcap
#cgo dragonfly LDFLAGS: -lpcap
#cgo freebsd LDFLAGS: -lpcap
#cgo openbsd LDFLAGS: -lpcap
#cgo netbsd LDFLAGS: -lpcap
#cgo darwin LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>
#include <stdint.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

const errorBufferSize = C.PCAP_ERRBUF_SIZE

type pcapPtr *C.pcap_t
type pcapPktHdr C.struct_pcap_pkthdr

func (h *pcapPktHdr) getSec() int64 {
	return int64(h.ts.tv_sec)
}

func (h *pcapPktHdr) getUsec() int64 {
	return int64(h.ts.tv_usec)
}

func (h *pcapPktHdr) getLen() int {
	return int(h.len)
}

func (h *pcapPktHdr) getCaplen() int {
	return int(h.caplen)
}

func pcapOpenLive(device string, snaplen int, pro int, timeout int) (*Pcap, error) {
	buf := (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	cptr := C.pcap_open_live(dev, C.int(snaplen), C.int(pro), C.int(timeout), buf)
	if cptr == nil {
		return nil, errors.New(C.GoString(buf))
	}
	return &Pcap{cptr: cptr}, nil
}

func openOffline(file string) (handle *Pcap, err error) {
	buf := (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))
	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	cptr := C.pcap_open_offline(cf, buf)
	if cptr == nil {
		return nil, errors.New(C.GoString(buf))
	}
	return &Pcap{cptr: cptr}, nil
}

func (p *Pcap) Close() {
	if p.cptr != nil {
		C.pcap_close(p.cptr)
	}
	p.cptr = nil
}

func (p *Pcap) pcapGeterr() error {
	return errors.New(C.GoString(C.pcap_geterr(p.cptr)))
}

func (p *Pcap) pcapStats() (*Stats, error) {
	var cstats C.struct_pcap_stat
	if C.pcap_stats(p.cptr, &cstats) < 0 {
		return nil, p.pcapGeterr()
	}
	return &Stats{
		PacketsReceived:  int(cstats.ps_recv),
		PacketsDropped:   int(cstats.ps_drop),
		PacketsIfDropped: int(cstats.ps_ifdrop),
	}, nil
}
