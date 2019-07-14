package layers

type LayerType int64

type Layer interface {
	// LayerType is the gopacket type for this layer.
	LayerType() LayerType
	// LayerContents returns the set of bytes that make up this layer.
	LayerContents() []byte
	// LayerPayload returns the set of bytes contained within this layer, not
	// including the layer itself.
	LayerPayload() []byte
}

// LinkLayer is the packet layer corresponding to TCP/IP layer 1 (OSI layer 2)
type LinkLayer interface {
	Layer
	LinkFlow() Flow
}

// NetworkLayer is the packet layer corresponding to TCP/IP layer 2 (OSI
// layer 3)
type NetworkLayer interface {
	Layer
	NetworkFlow() Flow
}

// TransportLayer is the packet layer corresponding to the TCP/IP layer 3 (OSI
// layer 4)
type TransportLayer interface {
	Layer
	TransportFlow() Flow
}

// ApplicationLayer is the packet layer corresponding to the TCP/IP layer 4 (OSI
// layer 7), also known as the packet payload.
type ApplicationLayer interface {
	Layer
	Payload() []byte
}
