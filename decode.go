package gopcap

type Decoder interface {
	Decode([]byte) error
}
